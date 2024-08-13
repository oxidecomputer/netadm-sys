// Copyright 2024 Oxide Computer Company

#![allow(clippy::uninlined_format_args)]

use colored::*;
use num_enum::TryFromPrimitiveError;
use oxnet::IpNet;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;
use tracing::debug;

/// Structures and functions for interacting with IP network configuration and
/// state.
pub mod ip;

/// Structures and functions for interacting with link-layer network
/// configuration and state.
pub mod link;

/// Structures and functions for interacting with routing configuration and
/// state.
pub mod route;

/// System-level machinery
pub mod sys;

/// Functions for managing RFC2367 keys
pub mod pf_key;

mod ioctl;
mod kstat;
mod ndpd;
mod nvlist;

/// Error variants returned by netadm_sys.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not implemented")]
    NotImplemented,
    #[error("kstat: {0}")]
    Kstat(String),
    #[error("ioctl: {0}")]
    Ioctl(String),
    #[error("io err: {0}")]
    Io(#[from] std::io::Error),
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
    #[error("unrecognized neighbor state: {0}")]
    NeighborState(#[from] TryFromPrimitiveError<ioctl::NeighborState>),
}

// Datalink management --------------------------------------------------------

/// Link flags specifiy if a link is active, persistent, or both.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
#[derive(Debug, PartialEq, Eq, Clone)]
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
    Overlay = 0x200,
    Misc = 0x400,
    Tfport = 0x800,
    All = 0xfff,
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
            LinkClass::Misc => write!(f, "misc"),
            LinkClass::Overlay => write!(f, "overlay"),
            LinkClass::Tfport => write!(f, "tfport"),
            LinkClass::All => write!(f, "all"),
        }
    }
}

/// Link state indicates the carrier status of the link.
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinkInfo {
    pub id: u32,
    pub name: String,
    pub flags: LinkFlags,
    pub class: LinkClass,
    pub state: LinkState,
    pub mac: [u8; 6],
    pub mtu: Option<u32>,
    pub over: u32,
}

impl LinkInfo {
    /// Get a [`LinkHandle`] for the link this object refers to.
    pub fn handle(&self) -> LinkHandle {
        LinkHandle::Id(self.id)
    }
    /// Get an updated [`LinkInfo`] instance.
    pub fn update(&mut self) -> Result<(), Error> {
        *self = get_link(&self.handle())?;
        Ok(())
    }
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
            Ok(id) => Self::Id(id),
            Err(_) => Self::Name(s.into()),
        })
    }
}

/// Get a vector of all Layer-2 links present on the system.
pub fn get_links() -> Result<Vec<LinkInfo>, Error> {
    crate::link::get_links()
}

/// Get a datalink with the given `id`.
pub fn get_link(handle: &LinkHandle) -> Result<LinkInfo, Error> {
    crate::link::get_link(handle.id()?)
}

/// Given a datalink name, return it's numeric id.
pub fn linkname_to_id(name: &str) -> Result<u32, Error> {
    crate::link::linkname_to_id(name)
}

/// Create a simnet link.
///
/// Simnet links are used in pairs. When a pair of simnet links is created,
/// whaterver ingreses into one flows to the other.
pub fn create_simnet_link(
    name: &str,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    debug!("creating simnet link {}", name);
    crate::link::create_simnet_link(name, flags)
}

/// Create a tfport link.
///
/// Each tfport link is layered on top of a mac device and is associated with
/// a 16-bit port number.  When the tfport driver receives a packet with a
/// "sidecar" header attached, it uses the port in that header to forward the
/// packet to the link associated with that port.  Packets that are transmitted
/// through a tfport will have a sidecar header prepended by the tfport driver
/// before forwarding them to the underlying mac device.
pub fn create_tfport_link(
    name: &str,
    over: &str,
    port: u16,
    mac: Option<String>,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    debug!("creating tfport link {}", name);
    crate::link::create_tfport_link(name, over, port, mac, flags)
}

/// Information about a single tfport link
pub struct TfportInfo {
    pub name: String,
    pub pkt_src: String,
    pub port: u16,
    pub mac: String,
}

/// Given the LinkHandle for a tfport, return the details of the link.
pub fn get_tfport_info(link: &LinkHandle) -> Result<TfportInfo, Error> {
    let link = get_link(link)?;
    if link.class != LinkClass::Tfport {
        return Err(Error::BadArgument(format!(
            "{} is not a tfport",
            link.name
        )));
    }

    let info = crate::ioctl::get_tfport_info(link.id).map_err(|_| {
        Error::Ioctl(format!("failed to get link details for {}", link.name))
    })?;

    let pkt_src = match crate::link::get_link(info.pktsrc_id) {
        Ok(l) => l.name,
        Err(_) => "unknown".to_string(),
    };

    let mac = {
        let m = &info.mac_addr;
        format!(
            "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    };

    Ok(TfportInfo {
        name: link.name,
        pkt_src,
        port: info.port,
        mac,
    })
}

/// Create a virtual NIC link.
///
/// Virtual NICs are devices that are attached to another device. Packets that
/// ingress the attached device also ingress the VNIC and vice versa.
pub fn create_vnic_link(
    name: &str,
    link: &LinkHandle,
    mac: Option<Vec<u8>>,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    crate::link::create_vnic_link(name, link.id()?, mac, flags)
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
#[derive(Debug, PartialEq, Eq, Clone)]
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IpInfo {
    pub ifname: String,
    pub index: i32,
    pub addr: IpAddr,
    pub mask: u32,
    pub family: u16,
    pub state: IpState,
}

impl IpInfo {
    /// Get the address object associated with this IP address.
    ///
    /// The return value is a tuple of the form (name, kind). Name is an illumos
    /// address object name of the form `link-name`/`address-name` and kind is
    /// the kind of address such as static, dhcp, etc.
    pub fn obj(&self) -> Result<(String, String), Error> {
        match crate::ip::ifname_to_addrobj(&self.ifname, self.family) {
            Ok((name, kind)) => Ok((name, kind)),
            Err(e) => Err(Error::Ipmgmtd(e)),
        }
    }
}

/// Get a list of all IP addresses on the system.
///
/// The return value is a map whose keys are data link names, and values are the
/// addresses associated with those links.
pub fn get_ipaddrs() -> Result<BTreeMap<String, Vec<IpInfo>>, Error> {
    crate::ioctl::get_ipaddrs()
    // TODO incorporate more persistent address information from here
    //let paddrs = crate::ip::get_persistent_ipinfo()
    //  .map_err(|e| anyhow!("{}", e))?;
}

/// Get information about a specific IP interface
pub use crate::ioctl::get_ipaddr_info;

/// Get neighbor information for a particular IP address.
pub use crate::ioctl::get_neighbor;

/// Create an IP address and give it the provided address object name.
///
/// Standard convention is to use a name of the form
/// `<datalink-name>/<interface-name>`.
pub fn create_ipaddr(name: impl AsRef<str>, addr: IpNet) -> Result<(), Error> {
    crate::ioctl::create_ipaddr(name, addr)
}

/// Enable generation of an IPv6 link-local address for an interface
pub fn enable_v6_link_local(
    ifname: impl AsRef<str>,
    addrname: impl AsRef<str>,
) -> Result<(), Error> {
    crate::ioctl::enable_v6_link_local(ifname.as_ref(), addrname.as_ref())
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

/// Get route information for the provided `destination`
pub use crate::route::add_route;

/// Add a route to `destination` via `gateway`.
pub use crate::route::get_route;

/// Ensure a route to `destination` via `gateway` is present.
///
/// Same as `add_route` except no error is returned if the route already exists
/// on the system.
pub use crate::route::ensure_route_present;

/// Delete a route to `destination` via `gateway`.
pub use crate::route::delete_route;

/// A wrapper for LinkInfo that deletes the associated link when dropped. Mostly
/// for testing purposes< carefully.
pub struct DropLink {
    pub info: LinkInfo,
}
impl DropLink {
    pub fn handle(&self) -> LinkHandle {
        self.info.handle()
    }
    pub fn update(&mut self) -> Result<(), Error> {
        self.info.update()
    }
}
impl Drop for DropLink {
    fn drop(&mut self) {
        if let Err(e) = delete_link(&self.info.handle(), self.info.flags) {
            println!("deleting {} failed: {}", self.info.name, e);
        }
    }
}
impl From<LinkInfo> for DropLink {
    fn from(info: LinkInfo) -> Self {
        Self { info }
    }
}

/// A wrapper for IpInfo that deletes the associated address when dropped. Mostly
/// for testing purposes< carefully.
pub struct DropIp {
    pub info: IpInfo,
}
impl Drop for DropIp {
    fn drop(&mut self) {
        let name = match self.info.obj() {
            Ok((name, _)) => name,
            Err(e) => {
                println!("delete {:?}: obj() failed: {}", self.info, e);
                return;
            }
        };
        if let Err(e) = delete_ipaddr(name) {
            println!("delete {:?} failed: {}", self.info, e);
        }
    }
}
impl From<IpInfo> for DropIp {
    fn from(info: IpInfo) -> Self {
        Self { info }
    }
}

/// A wrapper for a link name that deletes the associated IPv6 link localaddress
/// when dropped. Mostly for testing purposes< carefully.
pub struct DropLinkLocal {
    pub name: String,
}
impl Drop for DropLinkLocal {
    fn drop(&mut self) {
        if let Err(e) = delete_ipaddr(&self.name) {
            println!("delete link-local {:?} failed: {}", self.name, e);
        }
    }
}
