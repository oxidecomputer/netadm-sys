// Copyright 2021 Oxide Computer Company

use crate::ip::{self, addrobjname_to_addrobj};
use crate::ndpd::disable_autoconf;
use crate::sys::{
    self, dld_ioc_macaddrget_t, dld_ioc_macprop_t, dld_macaddrinfo_t,
    mac_prop_id_t_MAC_PROP_MTU, DLDIOC_GETMACPROP, DLDIOC_MACADDRGET,
    SIMNET_IOC_INFO, SIMNET_IOC_MODIFY,
};
use crate::{Error, IpInfo, IpPrefix, IpState, LinkFlags};
use libc::{free, malloc};
use libc::{
    sockaddr_in, sockaddr_in6, sockaddr_storage, AF_INET, AF_INET6, AF_UNSPEC,
};
use num_enum::TryFromPrimitive;
use rusty_doors::{door_call_slice, door_callp};
use socket2::{Domain, Socket, Type};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::fs::File;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::AsRawFd;
use std::ptr;
use tracing::{debug, warn};

macro_rules! ioctl {
    ( $fd:expr, $req:expr, $($args:expr),* ) => {{
        match libc::ioctl($fd, $req, $($args),*) {
            -1 => Err(Error::Ioctl(format!(
                "ioctl @{}={} {}: {}",
                stringify!($fd), $fd,
                stringify!($req),
                std::io::Error::last_os_error(),
            ))),
            x => Ok(x)
        }
    }}
}

// "rusty" ioctl where the first argument implements std::os::unix::io::AsRawFd
macro_rules! rioctl {
    ( $fd:expr, $req:expr, $($args:expr),* ) => {{
        ioctl!($fd.as_raw_fd(), $req, $($args),*)
    }}
}

#[repr(C)]
struct GetMacAddrIoc {
    get: dld_ioc_macaddrget_t,
    info: dld_macaddrinfo_t,
}

fn dld_fd() -> Result<File, Error> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/dld")
        .map_err(Error::Io)
}

#[repr(C)]
struct SimnetModifyIoc {
    link_id: u32,
    peer_link_id: u32,
    flags: u32,
}

#[repr(C)]
pub(crate) struct SimnetInfoIoc {
    pub(crate) link_id: u32,
    pub(crate) peer_link_id: u32,
    pub(crate) typ: u32,
    pub(crate) mac_len: u32,
    pub(crate) flags: u32,
    pub(crate) mac_addr: [u8; sys::MAXMACADDRLEN as usize],
}

pub(crate) fn get_simnet_info(link_id: u32) -> Result<SimnetInfoIoc, Error> {
    let fd = dld_fd()?;

    unsafe {
        let arg = SimnetInfoIoc {
            link_id,
            peer_link_id: 0,
            typ: 0,
            mac_len: 0,
            flags: 0,
            mac_addr: [0; sys::MAXMACADDRLEN as usize],
        };

        rioctl!(fd, SIMNET_IOC_INFO, &arg)?;

        Ok(arg)
    }
}

pub(crate) fn connect_simnet_peers(
    link_id: u32,
    peer_link_id: u32,
) -> Result<(), Error> {
    let fd = dld_fd()?;

    unsafe {
        let arg = SimnetModifyIoc {
            link_id,
            peer_link_id,
            flags: 0,
        };

        rioctl!(fd, SIMNET_IOC_MODIFY, &arg)?;
        Ok(())
    }
}

#[repr(C)]
pub(crate) struct TfportInfoIoc {
    pub(crate) link_id: u32,
    pub(crate) pktsrc_id: u32,
    pub(crate) port: u16,
    pub(crate) mac_len: u32,
    pub(crate) mac_addr: [u8; sys::ETHERADDRL as usize],
}

pub(crate) fn get_tfport_info(link_id: u32) -> Result<TfportInfoIoc, Error> {
    let fd = dld_fd()?;

    unsafe {
        let arg = TfportInfoIoc {
            link_id,
            pktsrc_id: 0,
            port: 0,
            mac_len: 0,
            mac_addr: [0; sys::ETHERADDRL as usize],
        };

        rioctl!(fd, sys::TFPORT_IOC_INFO, &arg)?;

        Ok(arg)
    }
}

#[allow(dead_code)]
#[repr(i32)]
pub enum VnicMacAddrType {
    Unknown = -1,
    Fixed,
    Random,
    Factory,
    Auto,
    Primary,
    Vrid,
}

#[allow(dead_code)]
#[repr(i32)]
pub enum MacPriorityLevel {
    Low,
    Medium,
    High,
    Reset,
}

#[allow(dead_code)]
#[repr(i32)]
pub enum MacCpuMode {
    Invalid = 0,
    Fanout = 1,
    Cpus,
}

const MRP_NCPUS: usize = 256;

#[repr(C)]
pub struct MacTxIntrCPUs {
    pub mtc_intr_cpu: [i32; MRP_NCPUS],
    pub mtc_retargeted_cpu: [i32; MRP_NCPUS],
}
impl Default for MacTxIntrCPUs {
    fn default() -> Self {
        Self {
            mtc_intr_cpu: [0; MRP_NCPUS],
            mtc_retargeted_cpu: [0; MRP_NCPUS],
        }
    }
}

#[repr(C)]
pub struct MacCPUsProps {
    pub ncpus: u32,
    pub cpus: [u32; MRP_NCPUS],
    pub rx_fanout_cnt: u32,
    pub rx_fanout_cpus: [u32; MRP_NCPUS],
    pub rx_pollid: u32,
    pub rx_workerid: u32,
    pub rx_intr_cpu: i32,
    pub tx_fanout_cpus: [i32; MRP_NCPUS],
    pub tx_intr_cpus: MacTxIntrCPUs,
    pub fanout_mode: MacCpuMode,
}
impl Default for MacCPUsProps {
    fn default() -> Self {
        Self {
            ncpus: 0,
            cpus: [0; MRP_NCPUS],
            rx_fanout_cnt: 0,
            rx_fanout_cpus: [0; MRP_NCPUS],
            rx_pollid: 0,
            rx_workerid: 0,
            rx_intr_cpu: 0,
            tx_fanout_cpus: [0; MRP_NCPUS],
            tx_intr_cpus: MacTxIntrCPUs::default(),
            fanout_mode: MacCpuMode::Fanout,
        }
    }
}

#[repr(C)]
pub union In6Data {
    pub parts: [u16; 8],
    pub align: u32,
}

impl Copy for In6Data {}
impl Clone for In6Data {
    fn clone(&self) -> Self {
        unsafe {
            let mut c = In6Data { parts: [0; 8] };
            for (i, x) in self.parts.iter().enumerate() {
                c.parts[i] = *x;
            }
            c
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct In6Addr {
    pub data: In6Data,
}

impl Default for In6Addr {
    fn default() -> Self {
        Self {
            data: In6Data { parts: [0; 8] },
        }
    }
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct MacIpaddr {
    pub version: u32,
    pub addr: In6Addr,
    pub netmask: u8,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(i32)]
pub enum MacDhcpCidFrom {
    Typed = 1,
    Hex,
    Str,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct MacDhcpCid {
    pub id: [u8; MPT_MAXCIDLEN],
    pub len: u32,
    pub form: MacDhcpCidFrom,
}
impl Default for MacDhcpCid {
    fn default() -> Self {
        Self {
            id: [0; MPT_MAXCIDLEN],
            len: 0,
            form: MacDhcpCidFrom::Typed,
        }
    }
}

const MPT_MAXCID: usize = 32;
const MPT_MAXIPADDR: usize = 32;
const MPT_MAXCIDLEN: usize = 256;

#[repr(C)]
pub struct MacProtect {
    pub types: u32,
    pub ipaddrcnt: u32,
    pub ipaddrs: [MacIpaddr; MPT_MAXIPADDR],
    pub cidcnt: u32,
    pub cids: [MacDhcpCid; MPT_MAXCID],
}

impl Default for MacProtect {
    fn default() -> Self {
        Self {
            types: 0,
            ipaddrcnt: 0,
            ipaddrs: [MacIpaddr::default(); MPT_MAXIPADDR],
            cidcnt: 0,
            cids: [MacDhcpCid::default(); MPT_MAXCID],
        }
    }
}

#[repr(C, packed(4))]
pub struct MacResourceProps {
    pub mask: u32,
    pub maxbw: u64,
    pub priority: MacPriorityLevel,
    pub cpus: MacCPUsProps,
    pub protect: MacProtect,
    pub nrxrings: u32,
    pub ntxrings: u32,
    pub pool: [u8; sys::MAXPATHLEN as usize],
}

impl Default for MacResourceProps {
    fn default() -> Self {
        Self {
            mask: 0,
            maxbw: 0,
            priority: MacPriorityLevel::Low,
            cpus: MacCPUsProps::default(),
            protect: MacProtect::default(),
            nrxrings: 0,
            ntxrings: 0,
            pool: [0; sys::MAXPATHLEN as usize],
        }
    }
}

#[repr(C)]
pub struct VnicInfoIoc {
    pub vnic_id: u32,
    pub link_id: u32,
    pub mac_addr_type: VnicMacAddrType,
    pub mac_len: u32,
    pub mac_addr: [u8; sys::MAXMACADDRLEN as usize],
    pub mac_slot: u32,
    pub mac_prefix_len: u32,
    pub vid: u16,
    pub vrid: u32,
    pub af: u32,
    pub force: bool,
    pub resource_props: MacResourceProps,
}

impl Default for VnicInfoIoc {
    fn default() -> Self {
        Self {
            vnic_id: 0,
            link_id: 0,
            mac_addr_type: VnicMacAddrType::Unknown,
            mac_len: 0,
            mac_addr: [0; sys::MAXMACADDRLEN as usize],
            mac_slot: 0,
            mac_prefix_len: 0,
            vid: 0,
            vrid: 0,
            af: 0,
            force: false,
            resource_props: MacResourceProps::default(),
        }
    }
}

pub(crate) fn get_vnic_info(link_id: u32) -> Result<VnicInfoIoc, Error> {
    let fd = dld_fd()?;

    unsafe {
        let arg = VnicInfoIoc {
            vnic_id: link_id,
            ..Default::default()
        };
        ioctl!(fd.as_raw_fd(), sys::VNIC_IOC_INFO, &arg)?;
        Ok(arg)
    }
}

pub(crate) fn get_macaddr(linkid: u32) -> Result<[u8; 6], Error> {
    let fd = dld_fd()?;

    unsafe {
        let arg = GetMacAddrIoc {
            get: dld_ioc_macaddrget_t {
                dig_linkid: linkid,
                dig_count: 1,
                dig_size: size_of::<dld_macaddrinfo_t>() as u32,
            },
            info: dld_macaddrinfo_t {
                dmi_slot: 0,
                dmi_flags: 0,
                dmi_addrlen: 0,
                dmi_addr: [0; 20],
                dmi_client_name: [0; 256],
                dma_client_linkid: 0,
            },
        };

        ioctl!(fd.as_raw_fd(), DLDIOC_MACADDRGET, &arg)?;

        let mut res: [u8; 6] = [0; 6];
        res[..6].clone_from_slice(&arg.info.dmi_addr[..6]);

        Ok(res)
    }
}

pub(crate) fn get_mtu(linkid: u32) -> Result<u32, Error> {
    let fd = dld_fd()?;

    let mut arg = dld_ioc_macprop_t::<u32> {
        pr_flags: 0,
        pr_linkid: linkid,
        pr_num: mac_prop_id_t_MAC_PROP_MTU,
        pr_perm_flags: 0,
        pr_name: [0; 256],
        pr_valsize: size_of::<u32>() as u32,
        pr_val: 0,
    };
    arg.pr_name[..3].copy_from_slice(&b"mtu".map(|u| u as i8));

    unsafe {
        ioctl!(fd.as_raw_fd(), DLDIOC_GETMACPROP, &mut arg)?;
    }

    Ok(arg.pr_val)
}

pub(crate) fn get_ipaddrs() -> Result<BTreeMap<String, Vec<IpInfo>>, Error> {
    let mut result: BTreeMap<String, Vec<IpInfo>> = BTreeMap::new();

    unsafe {
        // create sockets

        let s4 = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        let s6 = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

        // get number of interfaces

        let lifn = sys::lifnum {
            lifn_family: AF_UNSPEC as u16,
            lifn_flags: 0,
            lifn_count: 0,
        };

        rioctl!(s4, sys::SIOCGLIFNUM, &lifn)?;

        // get interfaces

        let mut ifs: Vec<sys::lifreq> = Vec::new();
        ifs.resize(lifn.lifn_count as usize, sys::lifreq::new());

        let lifc = sys::lifconf {
            lifc_family: AF_UNSPEC as u16,
            lifc_flags: (sys::LIFC_NOXMIT
                | sys::LIFC_TEMPORARY
                | sys::LIFC_ALLZONES
                | sys::LIFC_UNDER_IPMP) as i32,
            lifc_len: lifn.lifn_count * size_of::<sys::lifreq>() as i32,
            lifc_lifcu: sys::lifconf_lifcu {
                lifcu_buf: ifs.as_mut_ptr() as *mut c_char,
            },
        };

        rioctl!(s4, sys::SIOCGLIFCONF, &lifc)?;

        for x in ifs.iter() {
            let info = match ipaddr_info(x, &s4, &s6) {
                Ok(None) => continue,
                Ok(Some(info)) => info,
                Err(e) => {
                    warn!("{:?}", e);
                    continue;
                }
            };

            match result.get_mut(&info.ifname) {
                None => {
                    result.insert(info.ifname.clone(), vec![info]);
                }
                Some(v) => v.push(info),
            };
        }
    }

    Ok(result)
}

pub(crate) fn ipaddr_exists(objname: impl AsRef<str>) -> Result<bool, Error> {
    let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")?;

    // get address info
    let mut req: ip::IpmgmtAobjopArg = unsafe { std::mem::zeroed() };
    req.cmd = ip::IpmgmtCmd::AobjName2Addrobj;
    for (i, c) in objname.as_ref().chars().enumerate() {
        req.objname[i] = c as c_char;
    }

    let mut response: *mut ip::IpmgmtAobjopRval = unsafe {
        malloc(std::mem::size_of::<ip::IpmgmtAobjopRval>())
            as *mut ip::IpmgmtAobjopRval
    };

    let respp: *mut ip::IpmgmtAobjopRval = door_callp(
        f.as_raw_fd(),
        req,
        ptr::NonNull::new(&mut response).unwrap(), // null not possible
    );
    let resp = unsafe { *respp };
    if resp.err != 0 {
        if resp.err == sys::IpadmStatusT::NotFound as i32 {
            return Ok(false);
        }
        //TODO cast to enum and print that way, not correct to use errno
        //return Err(Error::Ipmgmtd(sys::err_string(resp.err)));
        return Ok(false);
    }

    if (resp.flags & LinkFlags::Active as u32) == 0 {
        return Ok(false);
    }

    Ok(true)
}

pub(crate) fn delete_ipaddr(objname: impl AsRef<str>) -> Result<(), Error> {
    let ifname = objname.as_ref().split('/').collect::<Vec<&str>>()[0];

    let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")?;

    // get address info
    let mut req: ip::IpmgmtAobjopArg = unsafe { std::mem::zeroed() };
    req.cmd = ip::IpmgmtCmd::AobjName2Addrobj;
    for (i, c) in objname.as_ref().chars().enumerate() {
        req.objname[i] = c as c_char;
    }

    let mut response: *mut ip::IpmgmtAobjopRval = unsafe {
        malloc(std::mem::size_of::<ip::IpmgmtAobjopRval>())
            as *mut ip::IpmgmtAobjopRval
    };

    let respp: *mut ip::IpmgmtAobjopRval = door_callp(
        f.as_raw_fd(),
        req,
        ptr::NonNull::new(&mut response).unwrap(), // null not possible
    );
    let resp = unsafe { *respp };
    if resp.err != 0 {
        return Err(Error::Ipmgmtd(sys::err_string(resp.err)));
    }

    let af = resp.family as i32;

    // delete the address from kernel
    let mut ior: sys::lifreq = unsafe { std::mem::zeroed() };
    let mut i = 0;
    for c in resp.ifname {
        if c == 0 {
            break;
        }
        ior.lifr_name[i] = c;
        i += 1;
    }
    if resp.lnum != 0 {
        ior.lifr_name[i] = ':' as c_char;
        i += 1;
        for c in resp.lnum.to_string().chars() {
            ior.lifr_name[i] = c as c_char;
            i += 1;
        }
    }

    let sock = match resp.family as i32 {
        libc::AF_INET => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
        libc::AF_INET6 => {
            if resp.lnum == 0 {
                match crate::ndpd::delete_addrs(ifname) {
                    Ok(_) => {}
                    Err(e) => println!("ndp delete addrs: {}", e),
                };
            }
            Socket::new(Domain::IPV6, Type::DGRAM, None)?
        }
        _ => {
            return Err(Error::BadArgument(format!(
                "unknown address family: {}",
                resp.family
            )));
        }
    };

    if resp.lnum == 0 {
        unsafe {
            ior.lifr_lifru.lifru_flags &= !(sys::IFF_UP as u64);
            rioctl!(sock, sys::SIOCSLIFFLAGS, &ior)?;

            if af == libc::AF_INET {
                let sin = &mut ior.lifr_lifru.lifru_addr
                    as *mut sockaddr_storage
                    as *mut sockaddr_in;
                (*sin).sin_family = AF_INET as u16;
                (*sin).sin_addr.s_addr = 0;
            } else if af == libc::AF_INET6 {
                let sin6 = &mut ior.lifr_lifru.lifru_addr
                    as *mut sockaddr_storage
                    as *mut sockaddr_in6;
                (*sin6).sin6_family = AF_INET6 as u16;
                (*sin6).sin6_addr.s6_addr = [0u8; 16];
            }

            rioctl!(sock, sys::SIOCSLIFADDR, &ior)?;
        }
    } else {
        unsafe { rioctl!(sock, sys::SIOCLIFREMOVEIF, &ior)? };
    }

    let mut ia: ip::IpmgmtAddrArg = unsafe { std::mem::zeroed() };
    ia.cmd = ip::IpmgmtCmd::ResetAddr;
    ia.flags = sys::IPMGMT_ACTIVE;
    ia.lnum = resp.lnum as u32;
    for (i, c) in objname.as_ref().chars().enumerate() {
        ia.objname[i] = c as c_char;
    }

    // delete the address from ipmgmtd
    unsafe {
        let mut response: *mut ip::IpmgmtRval =
            malloc(std::mem::size_of::<ip::IpmgmtRval>())
                as *mut ip::IpmgmtRval;

        let resp: *mut ip::IpmgmtRval = door_callp(
            f.as_raw_fd(),
            ia,
            ptr::NonNull::new(&mut response).unwrap(), // null not possible
        );

        if (*resp).err != 0 {
            free(response as *mut c_void);
            return Err(Error::Ipmgmtd(format!(
                "reset address: {}",
                sys::err_string((*resp).err)
            )));
        }
        free(response as *mut c_void);
    }

    unplumb_for_af(ifname, af)?;

    Ok(())
}

//TODO check auth?
pub(crate) fn create_ipaddr(
    name: impl AsRef<str>,
    addr: IpPrefix,
) -> Result<(), Error> {
    let parts: Vec<&str> = name.as_ref().split('/').collect();
    if parts.len() < 2 {
        return Err(Error::BadArgument(
            "Expected <ifname>/<addrname>".to_string(),
        ));
    }
    let ifname = parts[0];

    let (iff, sock) = match addr {
        IpPrefix::V4(_) => {
            let s4 = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
            (sys::IFF_IPV4.into(), s4)
        }
        IpPrefix::V6(_) => {
            let s6 = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
            (sys::IFF_IPV6.into(), s6)
        }
    };

    match is_plumbed_for_af(ifname, &sock) {
        true => {}
        false => {
            plumb_for_af(ifname, iff)?;
        }
    };

    create_ip_addr_static(ifname, name.as_ref(), addr, &sock)
}

fn is_plumbed_for_af(name: &str, sock: &Socket) -> bool {
    let mut req = crate::sys::lifreq::new();
    for (i, c) in name.chars().enumerate() {
        req.lifr_name[i] = c as c_char;
    }
    unsafe { matches!(rioctl!(sock, sys::SIOCGLIFFLAGS, &req), Ok(_)) }
}

fn plumb_for_af(name: &str, mut ifflags: u64) -> Result<(), Error> {
    // TODO not handling interfaces assigned to different zones correctly.
    // TODO not handling loopback as special case like libipadm does

    let ip_h = match dlpi::open(name, dlpi::sys::DLPI_NOATTACH) {
        Ok(h) => dlpi::DropHandle(h),
        Err(e) => {
            return Err(Error::Ioctl(format!(
                "DLPI open: {}: {}",
                e,
                sys::errno_string()
            )));
        }
    };
    let ip_fd = match ip_h.fd() {
        Ok(fd) => fd,
        Err(e) => {
            return Err(Error::Ioctl(format!("DLPI IP fd: {}", e)));
        }
    };

    // push ip module
    let ip_mod_name = CStr::from_bytes_with_nul(sys::IP_MOD_NAME).unwrap();
    unsafe { ioctl!(ip_fd, sys::I_PUSH, ip_mod_name.as_ptr())? };

    let spec = parse_ifspec(name);

    // create the new interface via SIOCSLIFNAME
    if (ifflags & (sys::IFF_IPV6 as u64)) != 0 {
        ifflags |= sys::IFF_NOLINKLOCAL;
    };
    let mut req = sys::lifreq::new();
    req.lifr_lifru.lifru_flags = ifflags;
    req.lifr_lifru1.lifru_ppa = spec.ppa;

    for (i, c) in name.chars().enumerate() {
        req.lifr_name[i] = c as c_char;
    }
    unsafe { ioctl!(ip_fd, sys::SIOCSLIFNAME, &req)? };

    // get flags for the interface
    unsafe { ioctl!(ip_fd, sys::SIOCGLIFFLAGS, &req)? };
    ifflags = unsafe { req.lifr_lifru.lifru_flags };

    let mux_fd = if (ifflags & (sys::IFF_IPV6 as u64)) != 0 {
        File::open("/dev/udp6")?
    } else {
        File::open("/dev/udp")?
    };

    // pop off unwanted modules
    loop {
        if unsafe { rioctl!(mux_fd, sys::I_POP, 0).is_err() } {
            break;
        }
    }

    // push on arp module
    let arp_mod_name = CStr::from_bytes_with_nul(sys::ARP_MOD_NAME).unwrap();
    unsafe { rioctl!(mux_fd, sys::I_PUSH, arp_mod_name)? };

    // check if ARP is not needed
    if (ifflags & ((sys::IFF_NOARP | sys::IFF_IPV6) as u64)) != 0 {
        unsafe {
            let res = rioctl!(mux_fd, sys::I_PLINK, ip_fd);

            return match res {
                Ok(ip_muxid) => {
                    // Stash the muxid to later use while unplumbing
                    let mut req = sys::lifreq::new();
                    for (i, c) in name.chars().enumerate() {
                        req.lifr_name[i] = c as c_char;
                    }
                    req.lifr_lifru.lif_muxid[0] = ip_muxid;
                    rioctl!(mux_fd, sys::SIOCSLIFMUXID, &mut req)?;

                    Ok(disable_autoconf(name)?)
                }
                Err(e) => Err(e),
            };
        }
    }

    // open arp dlpi
    let arp_h = match dlpi::open(name, dlpi::sys::DLPI_NOATTACH) {
        Ok(h) => dlpi::DropHandle(h),
        Err(e) => return Err(Error::Ioctl(format!("DLPI ARP open: {}", e))),
    };

    let arp_fd = match arp_h.fd() {
        Ok(fd) => fd,
        Err(e) => {
            return Err(Error::Ioctl(format!("DLPI ARP fd: {}", e)));
        }
    };

    unsafe { rioctl!(arp_fd, sys::I_PUSH, arp_mod_name)? };

    let mut req = sys::lifreq::new();
    req.lifr_lifru.lifru_flags = ifflags;
    req.lifr_lifru1.lifru_ppa = spec.ppa;
    for (i, c) in name.chars().enumerate() {
        req.lifr_name[i] = c as c_char;
    }
    let arg = &mut req as *mut sys::lifreq as *mut c_char;
    str_ioctl(
        arp_fd,
        sys::SIOCSLIFNAME,
        arg,
        size_of::<sys::lifreq>() as c_int,
    )?;

    // plink IP and arp streams
    let ip_muxid = unsafe { rioctl!(mux_fd, sys::I_PLINK, ip_fd)? };

    unsafe {
        let arp_muxid = match rioctl!(mux_fd, sys::I_PLINK, arp_fd) {
            Ok(muxid) => muxid,
            Err(e) => {
                // undo the plink of IP stream
                if let Err(e) = rioctl!(mux_fd, sys::I_PUNLINK, ip_muxid) {
                    println!("punlink failed: {}", e);
                }
                return Err(e);
            }
        };

        // Stash the muxids to later use while unplumbing
        let mut req = sys::lifreq::new();
        for (i, c) in name.chars().enumerate() {
            req.lifr_name[i] = c as c_char;
        }
        req.lifr_lifru.lif_muxid[0] = ip_muxid;
        req.lifr_lifru.lif_muxid[1] = arp_muxid;
        rioctl!(mux_fd, sys::SIOCSLIFMUXID, &mut req)?;
    }

    Ok(())
}

fn unplumb_for_af(name: &str, af: i32) -> Result<(), Error> {
    let mux_fd = if af == libc::AF_INET6 {
        File::open("/dev/udp6")?
    } else if af == libc::AF_INET {
        File::open("/dev/udp")?
    } else {
        return Err(Error::BadArgument(format!(
            "Invalid address family: {}",
            af
        )));
    };

    let mut req = sys::lifreq::new();
    for (i, c) in name.chars().enumerate() {
        req.lifr_name[i] = c as c_char;
    }

    let (ip_muxid, arp_muxid) = unsafe {
        rioctl!(mux_fd, sys::SIOCGLIFMUXID, &mut req)?;
        (req.lifr_lifru.lif_muxid[0], req.lifr_lifru.lif_muxid[1])
    };

    // pop off unwanted modules
    loop {
        if unsafe { rioctl!(mux_fd, sys::I_POP, 0).is_err() } {
            break;
        }
    }

    // push on arp module
    let arp_mod_name = CStr::from_bytes_with_nul(sys::ARP_MOD_NAME).unwrap();
    unsafe { rioctl!(mux_fd, sys::I_PUSH, arp_mod_name)? };

    unsafe {
        if arp_muxid != 0 && arp_muxid != -1 {
            if let Err(e) = rioctl!(mux_fd, sys::I_PUNLINK, arp_muxid) {
                println!("punlink failed: {}", e);
            }
        }
        if let Err(e) = rioctl!(mux_fd, sys::I_PUNLINK, ip_muxid) {
            println!("punlink failed: {}", e);
        }
    }

    Ok(())
}

fn str_ioctl(
    s: c_int,
    cmd: c_int,
    buf: *mut c_char,
    buflen: c_int,
) -> Result<c_int, Error> {
    let mut ioc = sys::strioctl::new();
    ioc.ic_cmd = cmd;
    ioc.ic_timeout = 0;
    ioc.ic_len = buflen;
    ioc.ic_dp = buf;

    unsafe { ioctl!(s, sys::I_STR, &ioc) }
}

pub struct IfSpec {
    pub ppa: u32,
    pub lun: u32,
    pub lunvalid: bool,
    pub devnm: [u8; sys::LIFNAMSIZ],
}

/// Parse a interface specification with the following format.
///
/// <name>[ppa][:lun]
///
/// - name: name of the device
/// - ppa: physical point of attachment (integer)
/// - lun: logical unit numnber (integer)
fn parse_ifspec(ifname: &str) -> IfSpec {
    let parts: Vec<&str> = ifname.split(':').collect();
    let (lun, lunvalid) = {
        match parts.len() {
            0 => (0, false),
            1 => (0, false),
            _ => match parts[1].parse::<u32>() {
                Ok(i) => (i, true),
                Err(_) => (0, false),
            },
        }
    };
    let name = parts[0].trim_end_matches(char::is_numeric);
    let ppa = {
        let s = &parts[0][..name.len()];
        s.parse::<u32>().unwrap_or(0)
    };

    let mut devnm = [0u8; sys::LIFNAMSIZ];
    for (i, c) in name.chars().enumerate() {
        devnm[i] = c as u8;
    }

    IfSpec {
        ppa,
        lun,
        lunvalid,
        devnm,
    }
}

/// Get information about a specific IP interface
pub fn get_ipaddr_info(name: &str) -> Result<IpInfo, Error> {
    unsafe {
        let (_, _, af, mut ifname, lifnum) = addrobjname_to_addrobj(name)
            .map_err(|e| Error::Ioctl(format!("get addrobj: {}", e)))?;

        let s4 = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        let s6 = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

        if lifnum > 0 {
            ifname = format!("{}:{}", ifname, lifnum);
        }

        let mut req = sys::lifreq::new();
        for (i, c) in ifname.chars().enumerate() {
            req.lifr_name[i] = c as c_char;
        }

        let ss = match af as i32 {
            libc::AF_INET => &s4,
            libc::AF_INET6 => {
                let sin6 = &mut req.lifr_lifru.lifru_addr
                    as *mut sockaddr_storage
                    as *mut sockaddr_in6;
                (*sin6).sin6_family = AF_INET6 as u16;
                &s6
            }
            _ => return Err(Error::NotFound(name.into())),
        };

        // get addr
        rioctl!(ss, sys::SIOCGLIFADDR, &req)?;

        match ipaddr_info(&req, &s4, &s6) {
            Ok(Some(info)) => Ok(info),
            Ok(None) => Err(Error::NotFound(name.into())),
            Err(e) => Err(e),
        }
    }
}

unsafe fn ipaddr_info(
    x: &sys::lifreq,
    s4: &Socket,
    s6: &Socket,
) -> Result<Option<IpInfo>, Error> {
    let _name = CStr::from_ptr(x.lifr_name.as_ptr());
    let name = match _name.to_str() {
        Ok(s) => s,
        Err(_) => {
            return Err(Error::Ioctl("interface name conversion".into()));
        }
    };

    let sa = x.lifr_lifru.lifru_addr;
    let addr = match sockaddr2ipaddr(&sa) {
        Some(addr) => addr,
        None => {
            // this typically means that an interface is plumbed but the ip
            // address has been removed, which is ok.
            return Ok(None);
        }
    };

    let ss = match sa.ss_family as i32 {
        AF_INET => &s4,
        AF_INET6 => &s6,
        _ => return Err(Error::Ioctl("unknown address family".to_string())),
    };

    // get index
    rioctl!(ss, sys::SIOCGLIFINDEX, x)?;
    let idx = x.lifr_lifru.lifru_index;

    // get netmask
    rioctl!(ss, sys::SIOCGLIFNETMASK, x)?;
    let _mask = x.lifr_lifru.lifru_addr;
    let mask = match sockaddr2ipaddr(&_mask) {
        Some(mask) => mask,
        None => {
            return Err(Error::Ioctl(
                "socaddr to ipaddr conversion".to_string(),
            ))
        }
    };

    // determine state

    rioctl!(ss, sys::SIOCGLIFFLAGS, x)?;
    let flags = x.lifr_lifru.lifru_flags;
    let state = {
        if flags & sys::IFF_UP as u64 != 0 {
            IpState::OK
        } else if flags & sys::IFF_RUNNING as u64 != 0 {
            rioctl!(ss, sys::SIOCGLIFDADSTATE, x)?;
            if x.lifr_lifru.lifru_dadstate
                == sys::glif_dad_state_t_DAD_IN_PROGRESS
            {
                IpState::Tentative
            } else {
                IpState::OK
            }
        } else {
            IpState::Inaccessible
        }
    };

    Ok(Some(IpInfo {
        addr,
        state,
        ifname: name.to_string(),
        index: idx,
        mask: ip_mask(mask),
        family: sa.ss_family,
    }))
}

pub(crate) fn enable_v6_link_local(
    ifname: &str,
    addrname: &str,
) -> Result<(), Error> {
    let objname = format!("{}/{}", ifname, addrname);

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

    if !is_plumbed_for_af(ifname, &sock) {
        plumb_for_af(ifname, sys::IFF_IPV6.into())?;
    }

    create_ip_addr_linklocal(&sock, ifname, &objname)
}

pub fn create_ip_addr_linklocal(
    sock: &Socket,
    ifname: &str,
    objname: &str,
) -> Result<(), Error> {
    let mut req = sys::lifreq::default();
    for (i, c) in ifname.chars().enumerate() {
        req.lifr_name[i] = c as c_char;
    }
    let (lifnum, kernel_ifname) = create_logical_interface_v6(sock, &req)?;

    let ll_template = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    unsafe {
        req.lifr_lifru.lifru_addr = std::mem::zeroed();

        let sin6 = &mut req.lifr_lifru.lifru_addr as *mut sockaddr_storage
            as *mut sockaddr_in6;

        // Set netmask to /10
        (*sin6).sin6_family = AF_INET6 as u16;
        (*sin6).sin6_addr.s6_addr = [
            0b11111111, 0b11000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        rioctl!(sock, sys::SIOCSLIFNETMASK, &req)?;

        // Set address. In the kernel SIOCSLIFADDR uses the ill_token associated
        // with this interface to create an EUI-64 address.
        (*sin6).sin6_addr.s6_addr = ll_template;
        rioctl!(sock, sys::SIOCSLIFPREFIX, &req)?;

        //let (kernel_ifname, lifnum) = parse_ifname(&req)?;

        let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")?;

        // add placeholder to ipmgmtd
        add_if_to_ipmgmtd(
            objname,
            ifname,
            AF_INET6 as u16,
            lifnum,
            &f,
            ip::AddrType::Ipv6Addrconf,
        )?;

        // ensure interface is up
        let mut req: sys::lifreq = std::mem::zeroed();
        for (i, c) in kernel_ifname.chars().enumerate() {
            req.lifr_name[i] = c as c_char;
        }
        rioctl!(sock, sys::SIOCGLIFFLAGS, &req)?;
        req.lifr_lifru.lifru_flags |= sys::IFF_UP as u64;
        rioctl!(sock, sys::SIOCSLIFFLAGS, &req)?;

        let intfidlen = 0;
        let stateless = true;
        let stateful = false;

        crate::ndpd::create_addrs(
            ifname, *sin6, intfidlen, stateless, stateful, objname,
        )
        .map_err(|e| Error::Ioctl(format!("ndp create addrs: {}", e)))?;

        ipmgmtd_persist(objname, ifname, lifnum, None, &f)?;
    }

    Ok(())
}

fn create_logical_interface_v6(
    sock: &Socket,
    req: &sys::lifreq,
) -> Result<(i32, String), Error> {
    unsafe {
        // first check if the 0th logical interface has an address
        rioctl!(sock, sys::SIOCGLIFADDR, req)?;
        let sin6 = &req.lifr_lifru.lifru_addr as *const sockaddr_storage
            as *const sockaddr_in6;

        // if addr is not unspecified, this logical interface is taken, create
        // a new one.
        if (*sin6).sin6_addr.s6_addr != [0u8; 16] {
            rioctl!(sock, sys::SIOCLIFADDIF, req)?;
        }

        let (kname, lifnum) = parse_ifname(req)?;
        Ok((lifnum, kname.into()))
    }
}

fn create_logical_interface_v4(
    sock: &Socket,
    req: &sys::lifreq,
) -> Result<(i32, String), Error> {
    unsafe {
        // first check if the 0th logical interface has an address
        rioctl!(sock, sys::SIOCGLIFADDR, req)?;
        let sin4 = &req.lifr_lifru.lifru_addr as *const sockaddr_storage
            as *const sockaddr_in;

        // if addr is not unspecified, this logical interface is taken, create
        // a new one.
        if (*sin4).sin_addr.s_addr != 0 {
            rioctl!(sock, sys::SIOCLIFADDIF, req)?;
        }

        let (kname, lifnum) = parse_ifname(req)?;
        Ok((lifnum, kname.into()))
    }
}

fn parse_ifname(req: &sys::lifreq) -> Result<(&str, i32), Error> {
    let ifname =
        unsafe { std::ffi::CStr::from_ptr(&req.lifr_name[0]).to_str()? };

    let parts: Vec<&str> = ifname.split(':').collect();
    let lifnum = match parts.len() {
        2 => parts[1].parse::<i32>().unwrap_or(0),
        _ => 0,
    };

    Ok((ifname, lifnum))
}

//TODO check auth?
pub(crate) fn create_ip_addr_static(
    ifname: impl AsRef<str>,
    objname: impl AsRef<str>,
    addr: IpPrefix,
    sock: &Socket,
) -> Result<(), Error> {
    unsafe {
        let mut req: sys::lifreq = std::mem::zeroed();
        for (i, c) in ifname.as_ref().chars().enumerate() {
            req.lifr_name[i] = c as c_char;
        }

        match addr {
            IpPrefix::V6(_) => {
                create_logical_interface_v6(sock, &req)?;
            }
            IpPrefix::V4(_) => {
                create_logical_interface_v4(sock, &req)?;
            }
        }

        // assign addr
        match addr {
            IpPrefix::V6(a) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET6 as u16;
                let sas =
                    &mut req.lifr_lifru.lifru_addr as *mut sockaddr_storage;

                let sa6 = sas as *mut sockaddr_in6;
                (*sa6).sin6_addr.s6_addr = a.addr.octets();
            }
            IpPrefix::V4(a) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET as u16;
                let sas =
                    &mut req.lifr_lifru.lifru_addr as *mut sockaddr_storage;
                let sa4 = sas as *mut sockaddr_in;
                (*sa4).sin_addr.s_addr = Into::<u32>::into(a.addr).to_be();
            }
        };
        rioctl!(sock, sys::SIOCSLIFADDR, &req)?;

        // assign netmask
        match addr {
            IpPrefix::V6(a) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET6 as u16;
                let sas =
                    &mut req.lifr_lifru.lifru_addr as *mut sockaddr_storage;

                let sa6 = sas as *mut sockaddr_in6;
                let mut addr: u128 = 0;
                for i in 0..a.mask {
                    addr |= 1 << (127 - i);
                }
                (*sa6).sin6_addr.s6_addr = Ipv6Addr::from(addr).octets();
            }
            IpPrefix::V4(a) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET as u16;
                let sas =
                    &mut req.lifr_lifru.lifru_addr as *mut sockaddr_storage;

                let sa4 = sas as *mut sockaddr_in;
                let mut addr: u32 = 0;
                for i in 0..a.mask {
                    addr |= 1 << i;
                }
                (*sa4).sin_addr.s_addr = addr;
            }
        };
        rioctl!(sock, sys::SIOCSLIFNETMASK, &req)?;

        // add if to ipmgmtd
        let (kernel_ifname, lifnum) = parse_ifname(&req)?;

        let af = match addr {
            IpPrefix::V6(_) => AF_INET6 as u16,
            IpPrefix::V4(_) => AF_INET as u16,
        };

        let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")?;

        add_if_to_ipmgmtd(
            objname.as_ref(),
            ifname.as_ref(),
            af,
            lifnum,
            &f,
            ip::AddrType::Static,
        )?;

        // set up
        let mut req: sys::lifreq = std::mem::zeroed();
        for (i, c) in kernel_ifname.chars().enumerate() {
            req.lifr_name[i] = c as c_char;
        }
        req.lifr_lifru.lifru_flags |= sys::IFF_UP as u64;
        rioctl!(sock, sys::SIOCSLIFFLAGS, &req)?;

        // ipmgmtd persist .. kindof
        ipmgmtd_persist(
            objname.as_ref(),
            ifname.as_ref(),
            lifnum,
            Some(addr),
            &f,
        )?;

        //TODO duplicate address detection
    };

    Ok(())
}

fn add_if_to_ipmgmtd(
    objname: &str,
    ifname: &str,
    af: u16,
    lifnum: i32,
    f: &File,
    kind: ip::AddrType,
) -> Result<(), Error> {
    // assign name
    let mut iaa: ip::IpmgmtAobjopArg = unsafe { std::mem::zeroed() };
    iaa.cmd = ip::IpmgmtCmd::AddrobjLookupAdd;
    for (i, c) in objname.chars().enumerate() {
        iaa.objname[i] = c as c_char;
    }
    for (i, c) in ifname.chars().enumerate() {
        iaa.ifname[i] = c as c_char;
    }
    iaa.family = af;
    iaa.atype = kind;

    let mut response: *mut ip::IpmgmtRval = unsafe {
        malloc(std::mem::size_of::<ip::IpmgmtRval>()) as *mut ip::IpmgmtRval
    };

    door_callp(
        f.as_raw_fd(),
        iaa,
        ptr::NonNull::new(&mut response).unwrap(), // null not possible
    );
    unsafe { free(response as *mut c_void) };

    // set logical interface number

    iaa = unsafe { std::mem::zeroed() };
    iaa.cmd = ip::IpmgmtCmd::AddrobjSetLifnum;
    for (i, c) in objname.chars().enumerate() {
        iaa.objname[i] = c as c_char;
    }
    for (i, c) in ifname.chars().enumerate() {
        iaa.ifname[i] = c as c_char;
    }
    iaa.lnum = lifnum;
    let family = af;
    iaa.family = family;
    iaa.atype = kind;

    let mut response: *mut ip::IpmgmtRval = unsafe {
        malloc(std::mem::size_of::<ip::IpmgmtRval>()) as *mut ip::IpmgmtRval
    };

    door_callp(
        f.as_raw_fd(),
        iaa,
        ptr::NonNull::new(&mut response).unwrap(), // null not possible
    );
    unsafe { free(response as *mut c_void) };

    Ok(())
}

fn ipmgmtd_persist(
    objname: &str,
    ifname: &str,
    lifnum: i32,
    addr: Option<IpPrefix>,
    f: &File,
) -> Result<(), Error> {
    let mut nvl = nvpair::NvList::new_unique_names();
    nvl.insert("_ifname", ifname)?;
    nvl.insert("_aobjname", objname)?;
    nvl.insert("_lifnum", &lifnum)?;

    match addr {
        Some(addr) => {
            let ahname = match addr {
                IpPrefix::V6(a) => a.addr.to_string(),
                IpPrefix::V4(a) => a.addr.to_string(),
            };

            let mut addr_nvl = nvpair::NvList::new_unique_names();
            addr_nvl.insert("_aname", ahname.as_str())?;
            let addr_nvl_name = match addr {
                IpPrefix::V6(_) => "_ipv6addr",
                IpPrefix::V4(_) => "_ipv4addr",
            };

            nvl.insert(addr_nvl_name, addr_nvl.as_ref())?;
            nvl.insert("up", "yes")?;
        }
        // XXX hack: assuming this is a v6 link local
        None => {
            let mut ll_nvl = nvpair::NvList::new_unique_names();
            //let ll_template: [u8;16] = [
            //    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            //ll_nvl.insert("_addr", &ll_template[..])?;
            let prefixlen: u32 = 0;
            ll_nvl.insert("prefixlen", &prefixlen)?;
            ll_nvl.insert("_stateless", "yes")?;
            ll_nvl.insert("_stateful", "no")?;
            nvl.insert("_intfid", ll_nvl.as_ref())?;
        }
    }

    let nvl_c = nvl.as_mut_ptr();
    let mut nvl_buf: *mut c_char = std::ptr::null_mut();
    let mut nvl_sz: nvpair_sys::size_t = 0;
    let ret = unsafe {
        nvpair_sys::nvlist_pack(
            nvl_c,
            &mut nvl_buf,
            &mut nvl_sz,
            nvpair_sys::NV_ENCODE_NATIVE,
            0,
        )
    };
    if ret != 0 {
        return Err(Error::NvPair(format!("{}", ret)));
    }

    let arg = ip::IpmgmtSetAddr {
        cmd: ip::IpmgmtCmd::SetAddr,
        flags: sys::IPMGMT_ACTIVE,
        nvlsize: nvl_sz as u32,
    };

    let mut buf: Vec<c_char> = Vec::new();

    let arg_bytes = unsafe {
        std::slice::from_raw_parts(
            (&arg as *const ip::IpmgmtSetAddr) as *const c_char,
            size_of::<ip::IpmgmtSetAddr>(),
        )
    };
    for c in arg_bytes {
        buf.push(*c);
    }

    let nvl_bytes =
        unsafe { std::slice::from_raw_parts(nvl_buf, nvl_sz as usize) };
    for c in nvl_bytes {
        buf.push(*c);
    }

    let resp: ip::IpmgmtRval = door_call_slice(f.as_raw_fd(), buf.as_slice());
    if resp.err != 0 {
        return Err(Error::Ipmgmtd(sys::err_string(resp.err)));
    }

    Ok(())
}

fn sockaddr2ipaddr(sa: &libc::sockaddr_storage) -> Option<IpAddr> {
    unsafe {
        match sa.ss_family as i32 {
            libc::AF_INET => {
                let sa4 = sa as *const sockaddr_storage as *const sockaddr_in;
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    (*sa4).sin_addr.s_addr,
                ))))
            }
            libc::AF_INET6 => {
                let sa6 = sa as *const sockaddr_storage as *const sockaddr_in6;
                let a6 = IpAddr::V6(Ipv6Addr::from((*sa6).sin6_addr.s6_addr));
                if a6.is_unspecified() {
                    return None;
                }
                Some(a6)
            }
            _ => None,
        }
    }
}

fn ip_mask(addr: IpAddr) -> u32 {
    match addr {
        IpAddr::V4(a4) => {
            let i = u32::from_be_bytes(a4.octets());
            i.leading_ones()
        }
        IpAddr::V6(a6) => {
            let i = u128::from_be_bytes(a6.octets());
            i.leading_ones()
        }
    }
}

#[repr(C)]
pub struct SimnetIocCreate {
    pub link_id: u32,
    pub typ: u32,
    pub mac_len: u32,
    pub flags: u32,
    pub mac_addr: [u8; sys::MAXMACADDRLEN as usize],
}

#[allow(dead_code)]
#[repr(i32)]
pub enum VnicIocDiag {
    _None,
    MacaddrNIC,
    MacaddrInUse,
    MacaddrInvalid,
    MacaddrLenInvalid,
    MacFactorySlotInvalid,
    MacFactorySlotUsed,
    MacFactorySlotAllUsed,
    MacFactoryNotSup,
    MacPrefixInvalid,
    MacPrefixLenInvalid,
    MacMarginInvalid,
    NoHwRings,
    MacMtuInvalid,
}

#[repr(C)]
pub struct VnicIocCreate {
    pub vnic_id: u32,
    pub link_id: u32,
    pub mac_addr_type: VnicMacAddrType,
    pub mac_len: u32,
    pub mac_addr: [u8; sys::MAXMACADDRLEN as usize],
    pub mac_prefix_len: u32,
    pub mac_slot: i32,
    pub vid: u16,
    pub vrid: u32,
    pub af: i32,
    pub status: u32,
    pub flags: u32,
    pub diag: VnicIocDiag,
    pub resource_props: MacResourceProps,
}

impl Default for VnicIocCreate {
    fn default() -> Self {
        Self {
            vnic_id: 0,
            link_id: 0,
            mac_addr_type: VnicMacAddrType::Unknown,
            mac_len: 0,
            mac_addr: [0; sys::MAXMACADDRLEN as usize],
            mac_prefix_len: 0,
            mac_slot: -1,
            vid: 0,
            vrid: 0,
            af: 0,
            status: 0,
            flags: 0,
            diag: VnicIocDiag::_None,
            resource_props: MacResourceProps::default(),
        }
    }
}

pub(crate) fn create_vnic(
    id: u32,
    link_id: u32,
    mac: Option<Vec<u8>>,
) -> Result<crate::LinkInfo, Error> {
    unsafe {
        let fd = dld_fd()?;

        debug!("creating vnic with id {}", id);

        let mut arg = VnicIocCreate {
            link_id,
            vnic_id: id,
            mac_addr_type: match mac {
                None => VnicMacAddrType::Auto,
                Some(_) => VnicMacAddrType::Fixed,
            },
            mac_len: match &mac {
                None => 0,
                Some(mac) => mac.len() as u32,
            },
            mac_prefix_len: match mac {
                None => 3,
                Some(_) => 0,
            },
            mac_slot: -1,
            vid: 0,
            vrid: 0,
            af: AF_UNSPEC,
            flags: 0,
            ..Default::default()
        };
        match mac {
            None => {
                // This seems to be the OUI prefix used for bhyve/virtio NICs
                // but I cannot find a documentation reference that actually
                // says so.
                arg.mac_addr[0] = 0x02;
                arg.mac_addr[1] = 0x08;
                arg.mac_addr[2] = 0x20;
            }
            Some(mac) => {
                if mac.len() > 20 {
                    return Err(Error::BadArgument("mac too long".to_string()));
                }
                for (i, x) in mac.iter().enumerate() {
                    arg.mac_addr[i] = *x;
                }
            }
        };

        sys::clear_errno();
        rioctl!(fd, sys::VNIC_IOC_CREATE, &arg)?;

        crate::link::get_link(id)
    }
}

pub(crate) fn create_simnet(
    id: u32,
    flags: crate::LinkFlags,
) -> Result<crate::LinkInfo, Error> {
    unsafe {
        let fd = dld_fd()?;

        debug!("creating simnet with id {}", id);

        let arg = SimnetIocCreate {
            link_id: id,
            typ: sys::DL_ETHER,
            mac_len: 0,
            flags: flags as u32,
            mac_addr: [0; sys::MAXMACADDRLEN as usize],
        };

        rioctl!(fd, sys::SIMNET_IOC_CREATE, &arg)?;
    }

    crate::link::get_link(id)
}

#[repr(C)]
pub struct SimnetIocDelete {
    link_id: u32,
    flags: u32,
}

pub(crate) fn delete_simnet(id: u32) -> Result<(), Error> {
    unsafe {
        let fd = dld_fd()?;
        let arg = SimnetIocDelete {
            link_id: id,
            flags: 0,
        };
        rioctl!(fd, sys::SIMNET_IOC_DELETE, &arg)?;
    }
    Ok(())
}

#[repr(C)]
pub struct TfportIocCreate {
    pub link_id: u32,
    pub pktsrc_id: u32,
    pub port: u16,
    pub mac_len: u32,
    pub mac_addr: [u8; sys::ETHERADDRL as usize],
}

pub(crate) fn create_tfport(
    link_id: u32,
    pktsrc_id: u32,
    port: u16,
    mac: Option<String>,
) -> Result<crate::LinkInfo, Error> {
    let (mac_len, mac_addr) = match mac {
        None => (0, [0; sys::ETHERADDRL as usize]),
        Some(mac) => {
            let mut mac_addr = [0; sys::ETHERADDRL as usize];
            let v: Vec<&str> = mac.split(':').collect();

            if v.len() != 6 {
                return Err(Error::BadArgument(
                    "invalid mac address".to_string(),
                ));
            }

            for (i, octet) in v.iter().enumerate() {
                mac_addr[i] = u8::from_str_radix(octet, 16).map_err(|_| {
                    Error::BadArgument("invalid mac address".to_string())
                })?;
            }
            (sys::ETHERADDRL, mac_addr)
        }
    };

    unsafe {
        let fd = dld_fd()?;
        debug!("creating tfport with id {}", link_id);
        let arg = TfportIocCreate {
            link_id,
            pktsrc_id,
            port,
            mac_len,
            mac_addr,
        };

        rioctl!(fd, sys::TFPORT_IOC_CREATE, &arg)?;
    }

    crate::link::get_link(link_id)
}

#[repr(C)]
pub struct TfportIocDelete {
    link_id: u32,
}

pub(crate) fn delete_tfport(link_id: u32) -> Result<(), Error> {
    unsafe {
        let fd = dld_fd()?;
        let arg = TfportIocDelete { link_id };
        rioctl!(fd, sys::TFPORT_IOC_DELETE, &arg)?;
    }
    Ok(())
}

#[repr(C)]
pub struct VnicIocDelete {
    link_id: u32,
}

pub(crate) fn delete_vnic(id: u32) -> Result<(), Error> {
    unsafe {
        let fd = dld_fd()?;
        let arg = VnicIocDelete { link_id: id };
        rioctl!(fd.as_raw_fd(), sys::VNIC_IOC_DELETE, &arg)?;
    }
    Ok(())
}

#[derive(Debug)]
pub struct Neighbor {
    pub state: NeighborState,
    pub l2_addr: Vec<i8>,
    pub flags: i32,
}

impl Neighbor {
    pub fn is_router(&self) -> bool {
        (self.flags & sys::NDF_ISROUTER_ON) != 0
    }
    pub fn is_anycast(&self) -> bool {
        (self.flags & sys::NDF_ANYCAST_ON) != 0
    }
    pub fn is_proxy(&self) -> bool {
        (self.flags & sys::NDF_PROXY_ON) != 0
    }
    pub fn is_static(&self) -> bool {
        (self.flags & sys::NDF_STATIC) != 0
    }
}

#[derive(TryFromPrimitive, Debug)]
#[repr(u8)]
pub enum NeighborState {
    Unchanged,
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
    Unreachable,
}

pub fn get_neighbor(ifname: &str, addr: Ipv6Addr) -> Result<Neighbor, Error> {
    let mut ior: sys::lifreq = unsafe { std::mem::zeroed() };
    let mut lifru_nd_req: sys::lif_nd_req = unsafe { std::mem::zeroed() };
    for (i, b) in ifname.bytes().enumerate() {
        ior.lifr_name[i] = b as i8;
    }

    let sin6 = &mut lifru_nd_req.lnr_addr as *mut sockaddr_storage
        as *mut sockaddr_in6;
    unsafe {
        (*sin6).sin6_family = AF_INET6 as u16;
        (*sin6).sin6_addr.s6_addr = addr.octets();
    }

    ior.lifr_lifru = sys::lifreq_ru { lifru_nd_req };

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;

    unsafe { rioctl!(sock, sys::SIOCLIFGETND, &ior)? };

    Ok(Neighbor {
        state: NeighborState::try_from(unsafe {
            ior.lifr_lifru.lifru_nd_req.lnr_state_create
        })?,
        l2_addr: unsafe { ior.lifr_lifru.lifru_nd_req.lnr_hdw_addr.to_vec() },
        flags: unsafe { ior.lifr_lifru.lifru_nd_req.lnr_flags },
    })
}

pub fn get_ifnum(ifname: &str, af: u16) -> Result<i32, Error> {
    let s = match af as i32 {
        AF_INET => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
        AF_INET6 => Socket::new(Domain::IPV6, Type::DGRAM, None)?,
        _ => return Err(Error::BadArgument("unknown address family".into())),
    };
    let mut ior: sys::lifreq = unsafe { std::mem::zeroed() };
    for (i, b) in ifname.as_bytes().iter().enumerate() {
        ior.lifr_name[i] = *b as i8;
    }
    unsafe {
        rioctl!(s, sys::SIOCGLIFINDEX, &ior)?;
    }
    Ok(unsafe { ior.lifr_lifru.lifru_index })
}
