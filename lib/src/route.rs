// Copyright 2021 Oxide Computer Company

use std::slice::from_raw_parts;
use std::mem::size_of;
use crate::{
    IpPrefix,
    sys:: {
        self,
        rt_msghdr,
        RTA_DST,
        RTA_GATEWAY,
        RTA_NETMASK,
    },
};

use libc::{
    close,
    read,
    write,
    sockaddr,
    sockaddr_in,
    sockaddr_in6,
    socket,
    AF_UNSPEC,
    AF_ROUTE,
    AF_INET,
    AF_INET6,
    SOCK_RAW,
};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

        let mut req = rt_msghdr::default();
        req.typ = sys::RTM_GETALL as u8;

        let mut n = write(
            sfd,
            (&req as *const rt_msghdr) as *const c_void,
            req.msglen as usize,
        );
        if n <= 0 {
            return Err(Error::SystemError(format!("write: {} {}", n, sys::errno)));
        }

        let mut buf: [u8; 10240] = [0; 10240];
        let mut p = buf.as_mut_ptr();

        n = read(sfd, buf.as_mut_ptr() as *mut c_void, 10240);
        loop {
            let hdr = p as *mut rt_msghdr;
            let dst = hdr.offset(1) as *mut sockaddr;
            let gw = match (*dst).sa_family as i32 {
                libc::AF_INET => {
                    dst.offset(1) as *mut sockaddr
                },
                libc::AF_INET6 => {
                    (dst as *mut sockaddr_in6).offset(1) as *mut sockaddr
                },
                _ => continue,
            };
            let mask = match (*dst).sa_family as i32 {
                libc::AF_INET => {
                    gw.offset(1) as *mut sockaddr
                }
                libc::AF_INET6 => {
                    (gw as *mut sockaddr_in6).offset(1) as *mut sockaddr
                },
                _ => continue,
            };

            result.push(Route {
                dest: match (*dst).sa_family as i32 {
                    libc::AF_INET => {
                        let dst = dst as *mut sockaddr_in;
                        IpAddr::V4(Ipv4Addr::from(
                                u32::from_be((*dst).sin_addr.s_addr)))
                    },
                    libc::AF_INET6 => {
                        let dst = dst as *mut sockaddr_in6;
                        IpAddr::V6(Ipv6Addr::from(
                                u128::from_be_bytes((*dst).sin6_addr.s6_addr)))
                    },
                    _ => {
                        p = (p as *mut u8).offset((*hdr).msglen as isize);
                        if p.offset_from(buf.as_mut_ptr()) >= n as isize {
                            break;
                        }
                        continue;
                    }
                },
                mask: match (*mask).sa_family as i32 {
                    libc::AF_INET => {
                        let mask = mask as *mut sockaddr_in;
                        u32::leading_ones(u32::from_be((*mask).sin_addr.s_addr))
                    }
                    libc::AF_INET6 => {
                        let mask = mask as *mut sockaddr_in6;
                        u128::leading_ones(
                            u128::from_be_bytes((*mask).sin6_addr.s6_addr))
                    }
                    _ => 0,
                },
                gw: match (*gw).sa_family as i32 {
                    libc::AF_INET => {
                        let gw = gw as *mut sockaddr_in;
                        IpAddr::V4(Ipv4Addr::from(
                                u32::from_be((*gw).sin_addr.s_addr)))
                    },
                    libc::AF_INET6 => {
                        let gw = gw as *mut sockaddr_in6;
                        IpAddr::V6(Ipv6Addr::from(
                                u128::from_be_bytes((*gw).sin6_addr.s6_addr)))
                    },
                    _ => {
                        match (*dst).sa_family as i32 {
                            libc::AF_INET => IpAddr::V4(Ipv4Addr::new(0,0,0,0)),
                            libc::AF_INET6 => IpAddr::V6(Ipv6Addr::new(
                                    0,0,0,0,0,0,0,0,
                            )),
                            _ => {
                                p = (p as *mut u8).offset((*hdr).msglen as isize);
                                if p.offset_from(buf.as_mut_ptr()) >= n as isize {
                                    break;
                                }
                                continue;
                            }
                        }
                    }
                },
            });

            p = (p as *mut u8).offset((*hdr).msglen as isize);
            if p.offset_from(buf.as_mut_ptr()) >= n as isize {
                break;
            }

        }

        close(sfd);
    }

    Ok(result)
}

pub fn add_route(
    destination: IpPrefix,
    gateway: IpAddr,
) -> Result<(), Error> {
    
    mod_route(destination, gateway, sys::RTM_ADD as u8)

}

pub fn delete_route(
    destination: IpPrefix,
    gateway: IpAddr,
) -> Result<(), Error> {
    
    mod_route(destination, gateway, sys::RTM_DELETE as u8)

}

fn mod_route(
    destination: IpPrefix,
    gateway: IpAddr,
    cmd: u8,
) -> Result<(), Error> {

    unsafe {

        let sfd = socket(AF_ROUTE as i32, SOCK_RAW as i32, AF_UNSPEC as i32);
        if sfd < 0 {
            return Err(Error::SystemError(format!("socket: {}", sys::errno)));
        }

        let mut req = rt_msghdr::default();
        req.typ = cmd;

        // set bitmask identifying addresses in message
        req.addrs = (RTA_DST | RTA_GATEWAY | RTA_NETMASK) as i32;

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(
            from_raw_parts(
                (&req as *const rt_msghdr) as *const u8,
                size_of::<rt_msghdr>(),
            ),
        );

        match destination {
            IpPrefix::V4(p) => {
                let sa = sockaddr_in{
                    sin_family: AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr{
                        s_addr: u32::from(p.addr),
                    },
                    sin_zero: [0; 8],
                };
                buf.extend_from_slice(
                    from_raw_parts(
                        (&sa as *const sockaddr_in) as *const u8,
                        size_of::<sockaddr_in>(),
                    ),
                );
            },
            IpPrefix::V6(p) => {
                let sa = sockaddr_in6{
                    sin6_family: AF_INET6 as u16,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr{
                        s6_addr: u128::from_le_bytes(p.addr.octets()).to_be_bytes(),
                    },
                    sin6_scope_id: 0,
                    __sin6_src_id: 0,
                };
                buf.extend_from_slice(
                    from_raw_parts(
                        (&sa as *const sockaddr_in6) as *const u8,
                        size_of::<sockaddr_in6>(),
                    ),
                );
            },
        };

        match gateway {
            IpAddr::V4(a) => {
                let sa = sockaddr_in{
                    sin_family: AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr{
                        s_addr: u32::from(a),
                    },
                    sin_zero: [0; 8],
                };
                buf.extend_from_slice(
                    from_raw_parts(
                        (&sa as *const sockaddr_in) as *const u8,
                        size_of::<sockaddr_in>(),
                    ),
                );
            },
            IpAddr::V6(a) => {
                let sa = sockaddr_in6{
                    sin6_family: AF_INET6 as u16,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr{
                        s6_addr: u128::from_le_bytes(a.octets()).to_be_bytes(),
                    },
                    sin6_scope_id: 0,
                    __sin6_src_id: 0,
                };
                buf.extend_from_slice(
                    from_raw_parts(
                        (&sa as *const sockaddr_in6) as *const u8,
                        size_of::<sockaddr_in6>(),
                    ),
                );
            },
        };

        match destination {
            IpPrefix::V4(p) => {
                let mut mask: u32 = 0;
                for i in 0..p.mask {
                    mask |= 1<<i;
                }
                let sa = sockaddr_in{
                    sin_family: AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr{
                        s_addr: mask.to_be(),
                    },
                    sin_zero: [0; 8],
                };
                buf.extend_from_slice(
                    from_raw_parts(
                        (&sa as *const sockaddr_in) as *const u8,
                        size_of::<sockaddr_in>(),
                    ),
                );
            },
            IpPrefix::V6(p) => {
                let mut mask: u128 = 0;
                for i in 0..p.mask {
                    mask |= 1<<i;
                }
                let sa = sockaddr_in6{
                    sin6_family: AF_INET6 as u16,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr{
                        s6_addr: mask.to_be_bytes(),
                    },
                    sin6_scope_id: 0,
                    __sin6_src_id: 0,
                };
                buf.extend_from_slice(
                    from_raw_parts(
                        (&sa as *const sockaddr_in6) as *const u8,
                        size_of::<sockaddr_in6>(),
                    ),
                );
            }
        };

        sys::errno = 0;
        let n = write(sfd, buf.as_ptr() as *const c_void, buf.len());
        if sys::errno != 0 {
            return Err(Error::SystemError(sys::errno_string()));
        }
        if n < buf.len() as isize {
            return Err(Error::SystemError(
                    format!("short write: {} < {}", n, buf.len())));
        }

    }

    Ok(())

}
