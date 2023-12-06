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

// These items are missing from non-illumos platforms (such as Linux).
// We define them by hand below so that cargo-check/cargo-clippy are still
// functional when not run on an illumos machine.
#[cfg(target_os = "illumos")]
use libc::{sockaddr_dl, AF_LINK};

#[cfg(not(target_os = "illumos"))]
#[repr(C)]
struct sockaddr_dl {
    sdl_family: u16,
    sdl_index: u16,
    sdl_type: u8,
    sdl_nlen: u8,
    sdl_alen: u8,
    sdl_slen: u8,
    sdl_data: [i8; 244],
}

#[cfg(not(target_os = "illumos"))]
const AF_LINK: std::os::raw::c_int = 25;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0} not implemented")]
    NotImplemented(String),
    #[error("system error {0}")]
    SystemError(String),
    #[error("bad argument: {0}")]
    BadArgument(String),
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
    pub ifx: Option<String>,
}

#[derive(Default, Debug)]
pub struct RtMsg {
    pub dst: Option<SocketAddr>,
    pub gw: Option<SocketAddr>,
    pub mask: Option<SocketAddr>,
    pub genmask: Option<SocketAddr>,
    pub ifp: Option<SocketDlAddr>,
    pub ifa: Option<SocketAddr>,
    pub author: Option<SocketAddr>,
    pub brd: Option<SocketAddr>,
    pub src: Option<SocketAddr>,
    pub delay: Option<u32>,
}

#[derive(Debug)]
pub struct SocketDlAddr {
    pub index: u16,
    pub name: String,
}

unsafe fn read_msg(buf: &[u8]) -> (RtMsg, &[u8]) {
    let hdr = buf.as_ptr() as *const rt_msghdr;
    let buf = &buf[std::mem::size_of::<rt_msghdr>()..];

    let (dst, buf) = get_addr_element(hdr, buf, RTA_DST as i32);
    let (gw, buf) = get_addr_element(hdr, buf, RTA_GATEWAY as i32);
    let (mask, buf) = get_addr_element(hdr, buf, RTA_NETMASK as i32);
    let (genmask, buf) = get_addr_element(hdr, buf, RTA_GENMASK as i32);
    let (ifp, buf) = get_dladdr_element(hdr, buf, RTA_IFP as i32);
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

unsafe fn get_dladdr_element(
    hdr: *const rt_msghdr,
    buf: &[u8],
    rta: i32,
) -> (Option<SocketDlAddr>, &[u8]) {
    if ((*hdr).addrs & rta) == 0 {
        return (None, buf);
    }
    let off = std::mem::size_of::<sockaddr_dl>();
    if buf.len() < off {
        return (None, buf);
    }

    let sa = &*(buf.as_ptr() as *mut sockaddr_dl);
    let index = sa.sdl_index;
    let mut name = String::new();
    let len = sa.sdl_nlen as usize;
    if len > 0 {
        let data: &[u8] =
            std::slice::from_raw_parts(sa.sdl_data.as_ptr() as *const u8, len);
        name = String::from_utf8_lossy(data).to_string();
    }

    (Some(SocketDlAddr { index, name }), &buf[off..])
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
            if buf.len() < off {
                return (None, buf);
            }
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

pub fn get_route(destination: IpPrefix) -> Result<Route, Error> {
    let mut sock = Socket::new(Domain::from(AF_ROUTE), Type::RAW, None)?;
    let mut msglen = size_of::<rt_msghdr>();
    let flags = match destination {
        IpPrefix::V4(p) => {
            if p.mask == 32 {
                msglen += size_of::<sockaddr_in>();
                sys::RTF_HOST as i32
            } else {
                msglen += size_of::<sockaddr_in>() * 2;
                0i32
            }
        }
        IpPrefix::V6(p) => {
            if p.mask == 128 {
                msglen += size_of::<sockaddr_in6>();
                sys::RTF_HOST as i32
            } else {
                msglen += size_of::<sockaddr_in6>() * 2;
                0i32
            }
        }
    };

    let mut req = rt_msghdr {
        addrs: (RTA_DST | RTA_IFP) as i32,
        typ: sys::RTM_GET as u8,
        version: sys::RTM_VERSION as u8,
        pid: std::process::id() as i32,
        seq: 47, //TODO
        msglen: msglen as u16,
        flags,
        ..Default::default()
    };
    if flags == 0 {
        req.addrs |= RTA_NETMASK as i32;
    }

    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(unsafe {
        from_raw_parts(
            (&req as *const rt_msghdr) as *const u8,
            size_of::<rt_msghdr>(),
        )
    });
    serialize_addr(&mut buf, destination.ip());
    if flags == 0 {
        serialize_addr(&mut buf, destination.mask_as_addr());
    }

    let n = sock.write(&buf)?;
    if n < buf.len() {
        return Err(Error::SystemError(format!(
            "short write: {} < {}",
            n,
            buf.len()
        )));
    }

    let mut buf: [u8; 10240] = [0; 10240];
    let n = sock.read(&mut buf)?;
    let buf = &buf[..n];

    let (msg, _b) = unsafe { read_msg(buf) };

    let dest = msg
        .dst
        .ok_or(Error::SystemError("missing destination".into()))?;
    let mask = msg.mask.ok_or(Error::SystemError("missing mask".into()))?;
    let gw = msg.gw.ok_or(Error::SystemError("missing gateway".into()))?;
    let ifx = match msg.ifp {
        Some(ifp) => Some(ifp.name),
        None => None,
    };

    Ok(Route {
        dest: dest.ip(),
        mask: match mask {
            SocketAddr::V4(s) => u32::from(*s.ip()).leading_ones(),
            SocketAddr::V6(s) => u128::from(*s.ip()).leading_ones(),
        },
        gw: gw.ip(),
        delay: 0,
        ifx,
    })
}

pub fn get_routes() -> Result<Vec<Route>, Error> {
    let mut sock = Socket::new(Domain::from(AF_ROUTE), Type::RAW, None)?;

    let req = rt_msghdr {
        addrs: (RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_DELAY | RTA_IFP)
            as i32,
        ..Default::default()
    };
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
        let ifx = match msg.ifp {
            Some(ifp) => Some(ifp.name.clone()),
            None => None,
        };

        let r = Route {
            dest,
            mask,
            gw,
            delay,
            ifx,
        };
        result.push(r);
    }

    Ok(result)
}

pub fn add_route(
    destination: IpPrefix,
    gateway: IpAddr,
    interface: Option<String>,
) -> Result<(), Error> {
    mod_route(destination, gateway, interface, sys::RTM_ADD as u8)
}

pub fn ensure_route_present(
    destination: IpPrefix,
    gateway: IpAddr,
    interface: Option<String>,
) -> Result<(), Error> {
    match add_route(destination, gateway, interface) {
        Err(Error::IoError(e)) => {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(Error::IoError(e))
            }
        }
        result => result,
    }
}

pub fn delete_route(
    destination: IpPrefix,
    gateway: IpAddr,
    interface: Option<String>,
) -> Result<(), Error> {
    mod_route(destination, gateway, interface, sys::RTM_DELETE as u8)
}

fn mod_route(
    destination: IpPrefix,
    gateway: IpAddr,
    interface: Option<String>,
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

    let flags = (sys::RTF_GATEWAY | sys::RTF_STATIC) as i32;
    let mut addrs = (RTA_DST | RTA_GATEWAY | RTA_NETMASK) as i32;
    if interface.is_some() {
        addrs |= sys::RTA_IFP as i32;
        msglen += size_of::<sockaddr_dl>();
    }

    let req = rt_msghdr {
        typ: cmd,
        msglen: msglen as u16,
        version: sys::RTM_VERSION as u8,
        addrs,
        pid: std::process::id() as i32,
        seq: 47, //TODO
        flags,
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

    if let Some(ifp) = interface {
        serialize_dladdr(&mut buf, &ifp, destination.ip())?;
    }

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

fn serialize_dladdr(
    buf: &mut Vec<u8>,
    ifname: &str,
    ip: IpAddr,
) -> Result<(), Error> {
    let bs = ifname.as_bytes();
    if bs.len() > 244 {
        return Err(Error::BadArgument("ifname too long".into()));
    }

    let proto = match ip {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    } as u16;
    let ifnum = crate::ioctl::get_ifnum(ifname, proto)
        .map_err(|x| Error::SystemError(x.to_string()))?;
    let mut sa = unsafe {
        sockaddr_dl {
            sdl_family: AF_LINK as u16,
            sdl_index: ifnum as u16,
            sdl_nlen: bs.len() as u8,
            ..std::mem::zeroed()
        }
    };
    for (i, b) in bs.iter().enumerate() {
        sa.sdl_data[i] = *b as i8;
    }
    buf.extend_from_slice(unsafe {
        from_raw_parts(
            (&sa as *const sockaddr_dl) as *const u8,
            size_of::<sockaddr_dl>(),
        )
    });
    Ok(())
}
