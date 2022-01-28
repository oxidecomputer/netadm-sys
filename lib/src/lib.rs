// Copyright 2021 Oxide Computer Company

use colored::*;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::net::{AddrParseError, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;
use thiserror::Error;
use tracing::debug;

pub mod ioctl;
pub mod ip;
pub mod kstat;
pub mod link;
pub mod ndpd;
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
    #[error("route error: {0}")]
    Route(#[from] route::Error),
    #[error("ndp error: {0}")]
    Ndp(String),
}

// Datalink management --------------------------------------------------------

/// Link flags specifiy if a link is active, persistent, or both.
#[derive(Copy, Clone, Debug, PartialEq)]
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
            LinkFlags::Persistent => {
                write!(f, "{}", "persistent".bright_blue())
            }
            LinkFlags::ActivePersistent => write!(
                f,
                "{} {}",
                "active".bright_green(),
                "persistent".bright_blue(),
            ),
        }
    }
}

/// Link class specifies the type of datalink.
#[derive(Debug, PartialEq)]
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
    All = 0x1ff,
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

/// Link state indicates the carrier status of the link.
#[derive(Debug, PartialEq)]
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

/// Information about a datalink.
#[derive(Debug, PartialEq)]
pub struct LinkInfo {
    pub id: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub class: LinkClass,
    pub state: LinkState,
    pub mac: [u8; 6],
    pub over: u32,
}

/// A link handle can be either a string or a numeric id.
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
        Ok(match s.parse::<u32>() {
            Ok(id) => LinkHandle::Id(id),
            Err(_) => LinkHandle::Name(s.to_string()),
        })
    }
}

/// Get a vector of all Layer-2 links present on the system.
pub fn get_links() -> Result<Vec<LinkInfo>, Error> {
    crate::link::get_links()
}

/// Get a datalink with the given `id`.
pub fn get_link(id: u32) -> Result<LinkInfo, Error> {
    crate::link::get_link(id)
}

/// Given a datalink name, return it's numeric id.
pub fn linkname_to_id(name: &str) -> Result<u32, Error> {
    crate::link::linkname_to_id(name)
}

/// Create a simnet link.
///
/// Simnet links are used in paris. When a pair of simnet links is created,
/// whaterver ingreses into one flows to the other.
pub fn create_simnet_link(
    name: &str,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    debug!("creating simnet link {}", name);
    crate::link::create_simnet_link(name, flags)
}

/// Create a virtual NIC link.
///
/// Virtual NICs are devices that are attached to another device. Packets that
/// ingress the attached device also ingress the VNIC and vice versa.
pub fn create_vnic_link(
    name: &str,
    link: &LinkHandle,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    crate::link::create_vnic_link(name, link.id()?, flags)
}

/// Delete a data link identified by `handle`.
pub fn delete_link(handle: &LinkHandle, flags: LinkFlags) -> Result<(), Error> {
    let id = match handle.id() {
        Err(Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
        Ok(id) => id,
    };

    crate::link::delete_link(id, flags)
}

/// Connect two simnet peers.
///
/// This means packets that ingress `a` will egress `a` to `b` and vice versa.
pub fn connect_simnet_peers(
    a: &LinkHandle,
    b: &LinkHandle,
) -> Result<(), Error> {
    let a_id = a.id()?;
    let b_id = b.id()?;

    crate::ioctl::connect_simnet_peers(a_id, b_id)
    /* only for persistent links
    crate::link::connect_simnet_peers(a_id, b_id)?;
    crate::link::connect_simnet_peers(b_id, a_id)
    */
}

// IP address management ------------------------------------------------------

/// The state of an IP address in the kernel.
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

/// Information in the kernel about an IP address.
#[derive(Debug)]
pub struct IpInfo {
    pub ifname: String,
    pub index: i32,
    pub addr: IpAddr,
    pub mask: u32,
    pub family: u16,
    pub state: IpState,
}

/// Get a list of all IP addresses on the system.
pub fn get_ipaddrs() -> Result<BTreeMap<String, Vec<IpInfo>>, Error> {
    crate::ioctl::get_ipaddrs()
    // TODO incorporate more persistent address information from here
    //let paddrs = crate::ip::get_persistent_ipinfo()
    //  .map_err(|e| anyhow!("{}", e))?;
}

/// Get information about a specific IP interface
pub use crate::ioctl::get_ipaddr_info;

/// Create an IP address and give it the provided address object name.
///
/// Standard convention is to use a name of the form
/// `<datalink-name>/<interface-name>`.
pub fn create_ipaddr(
    name: impl AsRef<str>,
    addr: IpPrefix,
) -> Result<(), Error> {
    crate::ioctl::create_ipaddr(name, addr)
}

/// Enable generation of an IPv6 link-local address for an interface
pub fn enable_v6_link_local(name: impl AsRef<str>) -> Result<(), Error> {
    crate::ioctl::enable_v6_link_local(name.as_ref())
}

/// Delete an IP address with the given address object name.
pub fn delete_ipaddr(name: impl AsRef<str>) -> Result<(), Error> {
    crate::ioctl::delete_ipaddr(name)
}

/// Check if an IP address with the given address object name exists.
pub fn ipaddr_exists(name: impl AsRef<str>) -> Result<bool, Error> {
    crate::ioctl::ipaddr_exists(name)
}

// Route management -----------------------------------------------------------

/// Get all routes present on the system.
pub fn get_routes() -> Result<Vec<crate::route::Route>, Error> {
    Ok(crate::route::get_routes()?)
}

/// Add a route to `destination` via `gateway`.
pub fn add_route(destination: IpPrefix, gateway: IpAddr) -> Result<(), Error> {
    Ok(crate::route::add_route(destination, gateway)?)
}

/// Ensure a route to `destination` via `gateway` is present.
///
/// Same as `add_route` except no error is returned if the route already exists
/// on the system.
pub fn ensure_route_present(
    destination: IpPrefix,
    gateway: IpAddr,
) -> Result<(), Error> {
    Ok(crate::route::ensure_route_present(destination, gateway)?)
}

/// Delete a route to `destination` via `gateway`.
pub fn delete_route(
    destination: IpPrefix,
    gateway: IpAddr,
) -> Result<(), Error> {
    Ok(crate::route::delete_route(destination, gateway)?)
}

/// An IP prefix is the leading bits of an IP address combined with a prefix
/// length indicating the number of leading bits that are significant.
#[derive(Debug, Clone, Copy)]
pub enum IpPrefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}

impl FromStr for IpPrefix {
    type Err = IpPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Ipv6Prefix::from_str(s) {
            Ok(a) => Ok(IpPrefix::V6(a)),
            _ => Ok(IpPrefix::V4(Ipv4Prefix::from_str(s)?)),
        }
    }
}

/// An IPv6 address with a mask to indicate how many leading bits are
/// significant.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Prefix {
    pub addr: Ipv6Addr,
    pub mask: u8,
}

/// An IPv4 address with a mask to indicate how many leading bits are
/// significant.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Prefix {
    pub addr: Ipv4Addr,
    pub mask: u8,
}

/// An error that inddicates what went wrong with parsing an IP prefix.
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
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            return Err(IpPrefixParseError::Cidr);
        }

        Ok(Ipv6Prefix {
            addr: Ipv6Addr::from_str(parts[0])?,
            mask: u8::from_str(parts[1])?,
        })
    }
}

impl FromStr for Ipv4Prefix {
    type Err = IpPrefixParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() < 2 {
            return Err(IpPrefixParseError::Cidr);
        }

        Ok(Ipv4Prefix {
            addr: Ipv4Addr::from_str(parts[0])?,
            mask: u8::from_str(parts[1])?,
        })
    }
}

#[cfg(test)]
mod tests;
