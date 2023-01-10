// Copyright 2021 Oxide Computer Company

//!
//! This file contains machinery for interacting with the illumos router socket.
//! This socket has the address family AF_ROUTE. Packets exchanged over an
//! AF_ROUTE socket have a special header described by `[sys::rt_msghdr]`.
//!
//! The structure of an AF_ROUTE message is the following.
//!
//! ```text
//! rt_msghdr: 74 bytes
//! route_addr_element_1: N bytes
//! route_addr_element_2: N bytes
//! ...
//! route_addr_element_N: N bytes
//! ```
//!
//! In the rt_msghdr there is a field `addrs` which is a bitmask that identifies
//! what address elements are present in the message. Members of this bitfield
//! are constants with the name format `RTA_<address name>`. These include
//!
//! ```text
//! RTA_DST =       1
//! RTA_GATEWAY =   (1<<1)
//! RTA_NETMASK =   (1<<2)
//! RTA_GENMASK =   (1<<3)
//! RTA_IFP =       (1<<4)
//! RTA_IFA =       (1<<5)
//! RTA_AUTHOR =    (1<<6)
//! RTA_BRD =       (1<<7)
//! RTA_SRC =       (1<<8)
//! RTA_DELAY =     (1<<9)
//! ```
//!
//! Address elements always appear in the order they are defined in the bitmask.
//! For example, a message containing RTA_DST RTA_GENMASK and RTA_AUTHOR will
//! always be structured as
//!
//! ```text
//! t_msghdr
//! TA_DST
//! TA_GENMASK
//! TA_AUTHOR
//! ```
//!

use crate::{
    sys::{
        self, rt_msghdr, RTA_AUTHOR, RTA_BRD, RTA_DELAY, RTA_DST, RTA_GATEWAY,
        RTA_GENMASK, RTA_IFA, RTA_IFP, RTA_NETMASK, RTA_SRC,
    },
    IpPrefix,
};
use std::io::{Read, Write};
use std::mem::size_of;
use std::slice::from_raw_parts;

use libc::{sockaddr, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, AF_ROUTE};

use socket2::{Domain, Socket, Type};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
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
    #[error("io error {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct Route {
    pub dest: IpAddr,
    pub mask: u32,
    pub gw: IpAddr,
    pub delay: u32,
}

#[derive(Default, Debug)]
pub struct RtMsg {
    pub dst: Option<SocketAddr>,
    pub gw: Option<SocketAddr>,
    pub mask: Option<SocketAddr>,
    pub genmask: Option<SocketAddr>,
    pub ifp: Option<SocketAddr>,
    pub ifa: Option<SocketAddr>,
    pub author: Option<SocketAddr>,
    pub brd: Option<SocketAddr>,
    pub src: Option<SocketAddr>,
    pub delay: Option<u32>,
}

unsafe fn read_msg(buf: &[u8]) -> (RtMsg, &[u8]) {
    let hdr = buf.as_ptr() as *const rt_msghdr;
    let buf = &buf[std::mem::size_of::<rt_msghdr>()..];

    let (dst, buf) = get_addr_element(hdr, buf, RTA_DST as i32);
    let (gw, buf) = get_addr_element(hdr, buf, RTA_GATEWAY as i32);
    let (mask, buf) = get_addr_element(hdr, buf, RTA_NETMASK as i32);
    let (genmask, buf) = get_addr_element(hdr, buf, RTA_GENMASK as i32);
    let (ifp, buf) = get_addr_element(hdr, buf, RTA_IFP as i32);
    let (ifa, buf) = get_addr_element(hdr, buf, RTA_IFA as i32);
    let (author, buf) = get_addr_element(hdr, buf, RTA_AUTHOR as i32);
    let (brd, buf) = get_addr_element(hdr, buf, RTA_BRD as i32);
    let (src, buf) = get_addr_element(hdr, buf, RTA_SRC as i32);
    let (delay, buf) = get_u32_element(hdr, buf, RTA_DELAY as i32);

    (
        RtMsg {
            dst,
            gw,
            mask,
            genmask,
            ifp,
            ifa,
            author,
            brd,
            src,
            delay,
        },
        buf,
    )
}

unsafe fn get_u32_element(
    hdr: *const rt_msghdr,
    buf: &[u8],
    rta: i32,
) -> (Option<u32>, &[u8]) {
    if ((*hdr).addrs & rta) == 0 {
        return (None, buf);
    }
    let value = *(buf.as_ptr() as *const u32);
    (Some(value), &buf[4..])
}

unsafe fn get_addr_element(
    hdr: *const rt_msghdr,
    buf: &[u8],
    rta: i32,
) -> (Option<SocketAddr>, &[u8]) {
    if ((*hdr).addrs & rta) == 0 {
        return (None, buf);
    }

    let dst = buf.as_ptr() as *mut sockaddr;
    match (*dst).sa_family as i32 {
        libc::AF_INET => {
            let dst = dst as *const sockaddr_in;
            let off = std::mem::size_of::<sockaddr_in>();
            (
                Some(
                    SocketAddrV4::new(
                        Ipv4Addr::from((*dst).sin_addr.s_addr.to_be()),
                        (*dst).sin_port,
                    )
                    .into(),
                ),
                &buf[off..],
            )
        }
        libc::AF_INET6 => {
            let dst = dst as *const sockaddr_in6;
            let off = std::mem::size_of::<sockaddr_in6>();
            (
                Some(
                    SocketAddrV6::new(
                        Ipv6Addr::from((*dst).sin6_addr.s6_addr),
                        (*dst).sin6_port,
                        (*dst).sin6_flowinfo,
                        (*dst).sin6_scope_id,
                    )
                    .into(),
                ),
                &buf[off..],
            )
        }
        _ => (None, buf),
    }
}

pub fn get_routes() -> Result<Vec<Route>, Error> {
    let mut sock = Socket::new(Domain::from(AF_ROUTE), Type::RAW, None)?;

    let mut req = rt_msghdr::default();
    req.addrs |= RTA_DELAY as i32;
    let req_data = unsafe {
        std::slice::from_raw_parts(
            (&req as *const rt_msghdr) as *const u8,
            std::mem::size_of::<rt_msghdr>(),
        )
    };
    let n = sock.write(req_data)?;
    if n < std::mem::size_of::<rt_msghdr>() {
        return Err(Error::SystemError(format!(
            "get routes: short write: {} < {}",
            n,
            std::mem::size_of::<rt_msghdr>(),
        )));
    }

    let mut buf: [u8; 10240] = [0; 10240];
    let n = sock.read(&mut buf)?;
    let mut buf = &buf[..n];

    let mut result = Vec::new();
    loop {
        if buf.len() < std::mem::size_of::<rt_msghdr>() {
            break;
        }
        let (msg, b) = unsafe { read_msg(buf) };
        buf = b;
        let dest = match msg.dst {
            Some(d) => d.ip(),
            None => continue,
        };
        let mask = match msg.mask {
            Some(m) => match m {
                SocketAddr::V4(s) => u32::from(*s.ip()).leading_ones(),
                SocketAddr::V6(s) => u128::from(*s.ip()).leading_ones(),
            },
            None => continue,
        };
        let gw = match msg.gw {
            Some(d) => d.ip(),
            None => continue,
        };
        let delay = msg.delay.unwrap_or(0);

        let r = Route {
            dest,
            mask,
            gw,
            delay,
        };
        result.push(r);
    }

    Ok(result)
}

pub fn add_route(destination: IpPrefix, gateway: IpAddr) -> Result<(), Error> {
    mod_route(destination, gateway, sys::RTM_ADD as u8)
}

pub fn ensure_route_present(
    destination: IpPrefix,
    gateway: IpAddr,
) -> Result<(), Error> {
    match add_route(destination, gateway) {
        Ok(_) => Ok(()),
        Err(Error::SystemError(msg)) => {
            //TODO this is terrible, include error codes in wrapped errors
            if msg.contains("exists") {
                Ok(())
            } else {
                Err(Error::SystemError(msg))
            }
        }
        Err(e) => Err(e),
    }
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
    let mut sock = Socket::new(Domain::from(AF_ROUTE), Type::RAW, None)?;
    let mut msglen = size_of::<rt_msghdr>();
    match destination {
        IpPrefix::V4(_) => {
            msglen += size_of::<sockaddr_in>() * 2;
        }
        IpPrefix::V6(_) => {
            msglen += size_of::<sockaddr_in6>() * 2;
        }
    };
    match gateway {
        IpAddr::V4(_) => {
            msglen += size_of::<sockaddr_in>();
        }
        IpAddr::V6(_) => {
            msglen += size_of::<sockaddr_in6>();
        }
    };

    let req = rt_msghdr {
        typ: cmd,
        msglen: msglen as u16,
        version: sys::RTM_VERSION as u8,
        addrs: (RTA_DST | RTA_GATEWAY | RTA_NETMASK) as i32,
        pid: std::process::id() as i32,

        //TODO
        seq: 47,

        //TODO more?
        // set bitmask identifying addresses in message
        flags: (sys::RTF_GATEWAY | sys::RTF_STATIC) as i32,

        ..Default::default()
    };

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(unsafe {
        from_raw_parts(
            (&req as *const rt_msghdr) as *const u8,
            size_of::<rt_msghdr>(),
        )
    });

    serialize_addr(&mut buf, destination.ip());
    serialize_addr(&mut buf, gateway);
    serialize_addr(&mut buf, destination.mask_as_addr());

    let n = sock.write(&buf)?;
    if n < buf.len() {
        return Err(Error::SystemError(format!(
            "short write: {} < {}",
            n,
            buf.len()
        )));
    }

    Ok(())
}

fn serialize_addr(buf: &mut Vec<u8>, a: IpAddr) {
    match a {
        IpAddr::V4(a) => {
            let sa = sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(a).to_be(),
                },
                sin_zero: [0; 8],
            };
            buf.extend_from_slice(unsafe {
                from_raw_parts(
                    (&sa as *const sockaddr_in) as *const u8,
                    size_of::<sockaddr_in>(),
                )
            });
        }
        IpAddr::V6(a) => {
            let sa = unsafe {
                sockaddr_in6 {
                    sin6_family: AF_INET6 as u16,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: a.octets(),
                    },
                    sin6_scope_id: 0,
                    ..std::mem::zeroed()
                }
            };
            buf.extend_from_slice(unsafe {
                from_raw_parts(
                    (&sa as *const sockaddr_in6) as *const u8,
                    size_of::<sockaddr_in6>(),
                )
            });
        }
    };
}
