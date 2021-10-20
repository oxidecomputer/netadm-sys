// Copyright 2021 Oxide Computer Company

use colored::*;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use tracing::debug;
use std::net::{Ipv4Addr, Ipv6Addr, AddrParseError};
use std::num::ParseIntError;
use thiserror::Error;

pub mod ioctl;
pub mod ip;
pub mod kstat;
pub mod link;
pub mod nvlist;
pub mod route;
mod sys;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not implemented")]
    NotImplemented,
    #[error("kstat: {0}")]
    Kstat(String),
    #[error("ioctl: {0}")]
    Ioctl(String),
    #[error("file i/o error: {0}")]
    File(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(#[from] std::str::Utf8Error),
    #[error("array conversion error: {0}")]
    Conversion(#[from] std::array::TryFromSliceError),
    #[error("dlmgmtd: {0}")]
    Dlmgmtd(String),
    #[error("ipmgmtd: {0}")]
    Ipmgmtd(String),
    #[error("bad argument: {0}")]
    BadArgument(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("nvpair: {0}")]
    NvPair(String),

}

#[derive(Debug)]
#[repr(i32)]
pub enum IpState {
    Disabled = 0,
    Duplicate = 1,
    Down = 2,
    Tentative = 3,
    OK = 4,
    Inaccessible = 5,
}

pub struct IpInfo {
    pub ifname: String,
    pub index: i32,
    pub addr: IpAddr,
    pub mask: u32,
    pub family: u16,
    pub state: IpState,
}

pub fn get_ipaddrs() -> Result<BTreeMap<String, Vec<IpInfo>>, Error> {
    let addrs = crate::ioctl::get_ipaddrs();

    // TODO incorporate more persistent address information from here
    //let paddrs = crate::ip::get_persistent_ipinfo()
    //  .map_err(|e| anyhow!("{}", e))?;

    addrs
}

pub fn create_ipaddr(
    name: impl AsRef<str>,
    addr: IpPrefix,
) -> Result<(), Error> {

    crate::ioctl::create_ipaddr(name, addr)
}

pub fn delete_ipaddr(
    name: impl AsRef<str>,
) -> Result<(), Error> {

    crate::ioctl::delete_ipaddr(name)
}


#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum LinkFlags {
    Active = 0x1,
    Persistent = 0x2,
    ActivePersistent = 0x3,
}

impl Display for LinkFlags {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            LinkFlags::Active => write!(f, "{}", "active".bright_green()),
            LinkFlags::Persistent => write!(f, "{}", "persistent".bright_blue()),
            LinkFlags::ActivePersistent => write!(
                f,
                "{} {}",
                "active".bright_green(),
                "persistent".bright_blue(),
            ),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub enum LinkClass {
    Phys = 0x01,
    Vlan = 0x02,
    Aggr = 0x04,
    Vnic = 0x08,
    Etherstub = 0x10,
    Simnet = 0x20,
    Bridge = 0x40,
    IPtun = 0x80,
    Part = 0x100,
    All = 0x01 | 0x02 | 0x03 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100,
}

impl Display for LinkClass {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            LinkClass::Phys => write!(f, "physical"),
            LinkClass::Vlan => write!(f, "vlan"),
            LinkClass::Aggr => write!(f, "aggr"),
            LinkClass::Vnic => write!(f, "vnic"),
            LinkClass::Etherstub => write!(f, "etherstub"),
            LinkClass::Simnet => write!(f, "simnet"),
            LinkClass::Bridge => write!(f, "bridge"),
            LinkClass::IPtun => write!(f, "iptun"),
            LinkClass::Part => write!(f, "part"),
            LinkClass::All => write!(f, "all"),
        }
    }
}

#[derive(Debug)]
pub enum LinkState {
    Unknown,
    Down,
    Up,
}

impl Display for LinkState {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            LinkState::Up => {
                write!(f, "{}", "up".bright_green())
            }
            LinkState::Down => {
                write!(f, "{}", "down".bright_red())
            }
            LinkState::Unknown => {
                write!(f, "{}", "unknown".bright_red())
            }
        }
    }
}

pub struct LinkInfo {
    pub id: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub class: LinkClass,
    pub state: LinkState,
    pub mac: [u8; 6],
    pub over: u32,
}

#[derive(Debug, Clone)]
pub enum LinkHandle {
    Id(u32),
    Name(String),
}

impl LinkHandle {
    pub fn id(&self) -> Result<u32, Error> {
        Ok(match self {
            LinkHandle::Id(id) => *id,
            LinkHandle::Name(name) => linkname_to_id(name)?,
        })
    }
}

impl FromStr for LinkHandle {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match u32::from_str_radix(s, 10) {
            Ok(id) => LinkHandle::Id(id),
            Err(_) => LinkHandle::Name(s.to_string()),
        })
    }
}

pub fn get_links() -> Result<Vec<LinkInfo>, Error> {
    crate::link::get_links()
}

pub fn get_link(id: u32) -> Result<LinkInfo, Error> {
    crate::link::get_link(id)
}

pub fn linkname_to_id(name: &String) -> Result<u32, Error> {
    crate::link::linkname_to_id(name)
}

pub fn create_simnet_link(name: &String, flags: LinkFlags) -> Result<LinkInfo, Error> {
    debug!("creating simnet link {}", name);
    crate::link::create_simnet_link(name, flags)
}

pub fn create_vnic_link(
    name: &String,
    link: &LinkHandle,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    crate::link::create_vnic_link(name, link.id()?, flags)
}

pub fn delete_link(handle: &LinkHandle, flags: LinkFlags) -> Result<(), Error> {
    let id = match handle.id() {
        Err(Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
        Ok(id) => id,
    };

    crate::link::delete_link(id, flags)
}

pub fn connect_simnet_peers(a: &LinkHandle, b: &LinkHandle) -> Result<(), Error> {
    let a_id = a.id()?;
    let b_id = b.id()?;

    crate::ioctl::connect_simnet_peers(a_id, b_id)
    /* only for persistent links
    crate::link::connect_simnet_peers(a_id, b_id)?;
    crate::link::connect_simnet_peers(b_id, a_id)
    */
}

#[derive(Debug, Clone, Copy)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl FromStr for IpPrefix {
    type Err = IpPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        match Ipv6Prefix::from_str(s) {
            Ok(a) => return Ok(IpPrefix::V6(a)),
            _ => Ok(IpPrefix::V4(Ipv4Prefix::from_str(s)?))
        }

    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub mask: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub mask: u8,
}

#[derive(Debug, Error)]
pub enum IpPrefixParseError {
    #[error("expected CIDR representation <addr>/<mask")]
    Cidr,

    #[error("address parse error: {0}")]
    Addr(#[from] AddrParseError),

    #[error("mask parse error: {0}")]
    Mask(#[from] ParseIntError),
}

impl FromStr for Ipv6Prefix {
    type Err = IpPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        let parts: Vec<&str> = s.split("/").collect();
        if parts.len() < 2 {
            return Err(IpPrefixParseError::Cidr);
        }

        Ok(Ipv6Prefix{
            addr: Ipv6Addr::from_str(parts[0])?,
            mask: u8::from_str(parts[1])?,
        })

    }
}

impl FromStr for Ipv4Prefix {
    type Err = IpPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {

        let parts: Vec<&str> = s.split("/").collect();
        if parts.len() < 2 {
            return Err(IpPrefixParseError::Cidr);
        }

        Ok(Ipv4Prefix{
            addr: Ipv4Addr::from_str(parts[0])?,
            mask: u8::from_str(parts[1])?,
        })

    }
}
