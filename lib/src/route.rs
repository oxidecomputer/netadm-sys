// Copyright 2021 Oxide Computer Company

use crate::sys::{
    self,
    rt_metrics,
    rt_msghdr,
};
use libc::{
    close,
    read,
    sockaddr_in,
    socket,
    write,
    AF_UNSPEC,
    AF_ROUTE,
    SOCK_RAW,
};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};
use std::os::raw::c_void;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0} not implemented")]
    NotImplemented(String),
    #[error("system error {0}")]
    SystemError(String),
    #[error("exists")]
    Exists,
    #[error("route does not exist")]
    DoesNotExist,
    #[error("insufficient resources")]
    InsufficientResources,
    #[error("insufficient permissions")]
    InsufficientPermissions,
}

pub struct Route {
    pub dest: IpAddr,
    pub mask: u32,
    pub gw: IpAddr,
}

pub fn get_routes() -> Result<Vec<Route>, Error> {
    let mut result = Vec::new();

    unsafe {
        let sfd = socket(AF_ROUTE as i32, SOCK_RAW as i32, AF_UNSPEC as i32);
        if sfd < 0 {
            return Err(Error::SystemError(format!("socket: {}", sys::errno)));
        }

        let req = rt_msghdr {
            rtm_msglen: size_of::<rt_msghdr>() as u16,
            rtm_version: sys::RTM_VERSION as u8,
            rtm_type: sys::RTM_GETALL as u8,
            rtm_addrs: 0,
            rtm_pid: sys::getpid(),
            rtm_seq: 1701,
            rtm_errno: 0,
            rtm_flags: 0,
            rtm_use: 0,
            rtm_inits: 0,
            rtm_index: 0,
            rtm_rmx: rt_metrics {
                rmx_locks: 0,
                rmx_mtu: 0,
                rmx_hopcount: 0,
                rmx_expire: 0,
                rmx_recvpipe: 0,
                rmx_sendpipe: 0,
                rmx_ssthresh: 0,
                rmx_rtt: 0,
                rmx_rttvar: 0,
                rmx_pksent: 0,
            },
        };

        let mut n = write(
            sfd,
            (&req as *const rt_msghdr) as *const c_void,
            req.rtm_msglen as usize,
        );
        if n <= 0 {
            return Err(Error::SystemError(format!("write: {} {}", n, sys::errno)));
        }

        let mut buf: [u8; 10240] = [0; 10240];
        let mut p = buf.as_mut_ptr();

        n = read(sfd, buf.as_mut_ptr() as *mut c_void, 10240);

        loop {
            let hdr = p as *mut rt_msghdr;
            let dst = hdr.offset(1) as *mut sockaddr_in;
            let gw = dst.offset(1) as *mut sockaddr_in;
            let mask = gw.offset(1) as *mut sockaddr_in;

            result.push(Route {
                dest: IpAddr::V4(Ipv4Addr::from(u32::from_be((*dst).sin_addr.s_addr))),
                mask: u32::leading_ones(u32::from_be((*mask).sin_addr.s_addr)),
                gw: IpAddr::V4(Ipv4Addr::from(u32::from_be((*gw).sin_addr.s_addr))),
            });

            p = mask.offset(1) as *mut u8;
            if p.offset_from(buf.as_mut_ptr()) >= n as isize {
                break;
            }
        }

        close(sfd);
    }

    Ok(result)
}
