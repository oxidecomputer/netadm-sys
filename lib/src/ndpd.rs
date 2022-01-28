use std::io::{Error, Read, Write};
use std::mem::size_of;
use std::os::unix::net::UnixStream;

use crate::sys;

#[repr(C)]
pub enum Cmd {
    DisableAutoconf,
    EnableAutoconf,
    CreateAddrs,
    DeleteAddrs,
}

#[repr(C)]
struct Msg {
    cmd: Cmd,
    ifname: [u8; sys::LIFNAMSIZ],
    intfid: libc::sockaddr_in6,
    intfidlen: i32,
    stateless: sys::boolean_t,
    stateful: sys::boolean_t,
    aobjname: [u8; sys::MAXNAMELEN as usize],
}

impl Msg {
    fn new(cmd: Cmd) -> Self {
        Msg {
            cmd: cmd,
            ifname: [0; sys::LIFNAMSIZ],
            intfid: libc::sockaddr_in6 {
                sin6_family: 0,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
                __sin6_src_id: 0,
            },
            intfidlen: 0,
            stateless: sys::boolean_t_B_FALSE,
            stateful: sys::boolean_t_B_FALSE,
            aobjname: [0; sys::MAXNAMELEN as usize],
        }
    }
}

fn send(msg: &Msg) -> std::io::Result<()> {
    let mut sock = UnixStream::connect("/var/run/in.ndpd_ipadm")?;

    // This is what dladm does, but here it crashes ndpd, i think this may be
    // because we need to poll before read on non blocking.
    //sock.set_nonblocking(true)?;

    let buf = unsafe {
        std::slice::from_raw_parts(
            (msg as *const Msg) as *const u8,
            size_of::<Msg>(),
        )
    };

    let mut n = 0;

    loop {
        n += sock.write(&buf[n..])?;
        if n >= size_of::<Msg>() {
            break;
        }
    }
    println!("wrote {}", n);

    let mut ret = [0u8; 4];
    n = 0;
    loop {
        n += sock.read(&mut ret[n..])?;
        if n >= 4 {
            break;
        }
    }
    let ret = i32::from_le_bytes(ret);
    println!("read {}={}", n, ret);

    match ret {
        0 => Ok(()),
        _ => Err(Error::from_raw_os_error(ret)),
    }
}

pub fn enable_autoconf(ifname: &str) -> std::io::Result<()> {
    let mut msg = Msg::new(Cmd::EnableAutoconf);
    msg.ifname[..ifname.len()].copy_from_slice(ifname.as_bytes());

    send(&msg)
}

pub fn disable_autoconf(ifname: &str) -> std::io::Result<()> {
    let mut msg = Msg::new(Cmd::DisableAutoconf);
    msg.ifname[..ifname.len()].copy_from_slice(ifname.as_bytes());

    send(&msg)
}

pub fn delete_addrs(ifname: &str) -> std::io::Result<()> {
    let mut msg = Msg::new(Cmd::DeleteAddrs);
    msg.ifname[..ifname.len()].copy_from_slice(ifname.as_bytes());

    send(&msg)
}

pub fn create_addrs(
    ifname: &str,
    intfid: libc::sockaddr_in6,
    intfidlen: i32,
    stateless: bool,
    stateful: bool,
    aobjname: &str,
) -> std::io::Result<()> {
    let stateful = if stateful {
        sys::boolean_t_B_TRUE
    } else {
        sys::boolean_t_B_FALSE
    };

    let stateless = if stateless {
        sys::boolean_t_B_TRUE
    } else {
        sys::boolean_t_B_FALSE
    };

    let mut msg = Msg {
        cmd: Cmd::CreateAddrs,
        ifname: [0; sys::LIFNAMSIZ],
        aobjname: [0; sys::MAXNAMELEN as usize],
        intfid,
        intfidlen,
        stateless,
        stateful,
    };
    msg.ifname[..ifname.len()].copy_from_slice(ifname.as_bytes());
    msg.aobjname[..aobjname.len()].copy_from_slice(aobjname.as_bytes());

    send(&msg)
}
