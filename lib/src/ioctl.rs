// Copyright 2021 Oxide Computer Company

use crate::sys::{
    self,
    dld_ioc_macaddrget_t,
    dld_macaddrinfo_t,
    DLDIOC_MACADDRGET,
    SIMNET_IOC_INFO,
    SIMNET_IOC_MODIFY,
};
use libc::{
    ioctl,
    close,
    socket,
    sockaddr_in,
    sockaddr_in6,
    sockaddr_storage,
    AF_INET,
    AF_INET6,
    AF_UNSPEC,
    SOCK_DGRAM,
};
use crate::ip;
use crate::{
    IpInfo,
    IpState,
    LinkFlags,
    Error,
    IpPrefix,
};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use tracing::{debug, warn};
use libc::{malloc, free};
use std::os::raw::{c_char, c_void, c_int};
use rusty_doors::{door_callp, door_call_slice};

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
        .map_err(|e| Error::File(e))
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
            link_id: link_id,
            peer_link_id: 0,
            typ: 0,
            mac_len: 0,
            flags: 0,
            mac_addr: [0; sys::MAXMACADDRLEN as usize],
        };
        let ret = ioctl(fd.as_raw_fd(), SIMNET_IOC_INFO, &arg);
        if ret != 0 {
            return Err(Error::Ioctl("ioctl SIMNET_IOC_INFO".to_string()));
        }
        Ok(arg)
    }
}

pub(crate) fn connect_simnet_peers(link_id: u32, peer_link_id: u32)
-> Result<(), Error> {
    let fd = dld_fd()?;

    unsafe {
        let arg = SimnetModifyIoc {
            link_id: link_id,
            peer_link_id: peer_link_id,
            flags: 0,
        };
        let ret = ioctl(fd.as_raw_fd(), SIMNET_IOC_MODIFY, &arg);
        if ret != 0 {
            return Err(Error::Ioctl("ioctl SIMNET_IOC_MODIFY".to_string()));
        }
        Ok(())
    }
}

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

#[repr(i32)]
pub enum MacPriorityLevel {
    Low,
    Medium,
    High,
    Reset,
}

#[repr(i32)]
pub enum MacCpuMode {
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
        let ret = ioctl(fd.as_raw_fd(), sys::VNIC_IOC_INFO, &arg);
        if ret != 0 {
            return Err(Error::Ioctl("ioctl VNIC_IOC_INFO".to_string()));
        }

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

        let ret = ioctl(fd.as_raw_fd(), DLDIOC_MACADDRGET, &arg);
        if ret != 0 {
            return Err(Error::Ioctl("ioctl DLDIOC_MACADDRGET".to_string()));
        }

        let mut res: [u8; 6] = [0; 6];

        for i in 0..6 {
            res[i] = arg.info.dmi_addr[i];
        }

        return Ok(res);
    }
}

pub(crate) fn get_ipaddrs() -> Result<BTreeMap<String, Vec<IpInfo>>, Error> {
    let mut result: BTreeMap<String, Vec<IpInfo>> = BTreeMap::new();

    unsafe {
        // create sockets

        let s4 = socket(AF_INET as i32, SOCK_DGRAM as i32, 0);
        if s4 < 0 {
            return Err(Error::Ioctl("socket 4".to_string()));
        }
        let s6 = socket(AF_INET6 as i32, SOCK_DGRAM as i32, 0);
        if s6 < 0 {
            close(s4);
            return Err(Error::Ioctl("socket 6".to_string()));
        }

        // get number of interfaces

        let lifn = sys::lifnum {
            lifn_family: AF_UNSPEC as u16,
            lifn_flags: 0,
            lifn_count: 0,
        };

        let mut ret = ioctl(s4, sys::SIOCGLIFNUM, &lifn);
        if ret != 0 {
            close(s4);
            close(s6);
            return Err(Error::Ioctl("ioctl SIOCGLIFNUM".to_string()));
        }

        // get interfaces

        let mut ifs: Vec<sys::lifreq> = Vec::new();
        ifs.resize(
            lifn.lifn_count as usize,
            sys::lifreq::new() 
        );

        let lifc = sys::lifconf {
            lifc_family: AF_UNSPEC as u16,
            lifc_flags: (sys::LIFC_NOXMIT
                | sys::LIFC_TEMPORARY
                | sys::LIFC_ALLZONES
                | sys::LIFC_UNDER_IPMP) as i32,
            lifc_len: lifn.lifn_count * size_of::<sys::lifreq>() as i32,
            lifc_lifcu: sys::lifconf_lifcu {
                lifcu_buf: ifs.as_mut_ptr() as *mut i8,
            },
        };

        ret = ioctl(s4, sys::SIOCGLIFCONF, &lifc);
        if ret != 0 {
            close(s4);
            close(s6);
            return Err(Error::Ioctl("ioctl SIOCGLIFCONF".to_string()));
        }

        for x in ifs.iter() {

            let info = match ipaddr_info(x, s4, s6) {
                Ok(info) => info,
                Err(e) => {
                    warn!("{:?}", e);
                    continue;
                }
            };

            match result.get_mut(&info.ifname) {
                None => { result.insert(info.ifname.clone(), vec![ info ]); },
                Some(v) => v.push(info),
            };

        }

        close(s4);
        close(s6);
    }

    Ok(result)
}

pub(crate) fn ipaddr_exists(
    objname: impl AsRef<str>,
) -> Result<bool, Error> {

    let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")?;

    // get address info
    let mut req: ip::IpmgmtAobjopArg = unsafe { std::mem::zeroed() };
    req.cmd = ip::IpmgmtCmd::AobjName2Addrobj;
    for (i, c) in objname.as_ref().chars().enumerate() {
        req.objname[i] = c as i8;
    }

    let mut response: *mut ip::IpmgmtAobjopRval = unsafe {
            malloc(std::mem::size_of::<ip::IpmgmtAobjopRval>())
                as *mut ip::IpmgmtAobjopRval
    };

    let respp: *mut ip::IpmgmtAobjopRval = door_callp(
        f.as_raw_fd(),
        req,
        &mut response,
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


    return Ok(true);

}

// TODO this is not completely deleting the address, a reference is still
// hanging out in ipmgmtd, look to see what ipadm is doing here ....
pub(crate) fn delete_ipaddr(
    objname: impl AsRef<str>,
) -> Result<(), Error> {

    let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")?;

    // get address info
    let mut req: ip::IpmgmtAobjopArg = unsafe { std::mem::zeroed() };
    req.cmd = ip::IpmgmtCmd::AobjName2Addrobj;
    for (i, c) in objname.as_ref().chars().enumerate() {
        req.objname[i] = c as i8;
    }

    let mut response: *mut ip::IpmgmtAobjopRval = unsafe {
            malloc(std::mem::size_of::<ip::IpmgmtAobjopRval>()) 
                as *mut ip::IpmgmtAobjopRval
    };

    let respp: *mut ip::IpmgmtAobjopRval = door_callp(
        f.as_raw_fd(),
        req,
        &mut response,
    );
    let resp = unsafe { *respp };
    if resp.err != 0 {
        return Err(Error::Ipmgmtd(sys::err_string(resp.err)));
    }

    // delete the address from kernel
    let mut ior: sys::lifreq = unsafe { std::mem::zeroed() };
    let mut i = 0;
    for c in resp.ifname {
        if c == 0 {
            break;
        }
        ior.lifr_name[i] = c;
        i+=1;
    }
    if resp.lnum != 0 {
        ior.lifr_name[i] = ':' as i8;
        i+=1;
        for c in resp.lnum.to_string().chars() {
            ior.lifr_name[i] = c as i8;
            i+=1;
        }
    }

    let sock = match resp.family as i32 {
        libc::AF_INET => {
            let s4 = unsafe{ socket(AF_INET as i32, SOCK_DGRAM as i32, 0) };
            if s4 < 0 {
                return Err(Error::Ioctl("socket 4".to_string()));
            }
            s4
        }
        libc::AF_INET6 => {
            let s6 = unsafe{ socket(AF_INET6 as i32, SOCK_DGRAM as i32, 0) };
            if s6 < 0 {
                return Err(Error::Ioctl("socket 6".to_string()));
            }
            s6
        }
        _ => {
            return Err(Error::BadArgument(
                    format!("unknown address family: {}", resp.family)));
        }
    };

    if resp.lnum == 0 {
        let ret = unsafe{ ioctl(sock, sys::SIOCSLIFADDR, &ior) };
        if ret != 0 {
            unsafe{ close(sock) };
            return Err(Error::Ioctl("ioctl SIOCSLIFADDR".to_string()));
        }
    } else  {
        let ret = unsafe{ ioctl(sock, sys::SIOCLIFREMOVEIF, &ior) };
        if ret != 0 {
            unsafe{ close(sock) };
            return Err(Error::Ioctl("ioctl SIOCLIFREMOVEIF".to_string()));
        }
    }

    let mut ia: ip::IpmgmtAddrArg = unsafe{ std::mem::zeroed() };
    ia.cmd = ip::IpmgmtCmd::ResetAddr;
    ia.flags = sys::IPMGMT_ACTIVE;
    ia.lnum = resp.lnum as u32;
    for (i, c) in objname.as_ref().chars().enumerate() {
        ia.objname[i] = c as i8;
    }

    // delete the address from ipmgmtd
    unsafe {
        let mut response: *mut ip::IpmgmtRval = malloc(std::mem::size_of::<
            ip::IpmgmtRval,
            >()) as *mut ip::IpmgmtRval;
        let resp: *mut ip::IpmgmtRval = door_callp(f.as_raw_fd(), ia, &mut response);
        if (*resp).err != 0 {
            free(response as *mut c_void);
            close(sock);
            return Err(Error::Ipmgmtd(
                    format!("reset address: {}", sys::err_string((*resp).err))
            ));
        }
        free(response as *mut c_void);
        close(sock);
    }

    Ok(())

}


//TODO check auth?
pub(crate) fn create_ipaddr(
    name: impl AsRef<str>,
    addr: IpPrefix,
) -> Result<(), Error> {

    let parts: Vec<&str> = name.as_ref().split("/").collect();
    if parts.len() < 2 {
        return Err(Error::BadArgument("Expected <ifname>/<addrname>".to_string()));
    }
    let ifname = parts[0];

    let (iff, sock) = match addr {
        IpPrefix::V4(_) => {
            let s4 = unsafe{ socket(AF_INET as i32, SOCK_DGRAM as i32, 0) };
            if s4 < 0 {
                return Err(Error::Ioctl("socket 4".to_string()));
            }
            (sys::IFF_IPV4, s4)
        }
        IpPrefix::V6(_) => {
            let s6 = unsafe{ socket(AF_INET6 as i32, SOCK_DGRAM as i32, 0) };
            if s6 < 0 {
                return Err(Error::Ioctl("socket 6".to_string()));
            }
            (sys::IFF_IPV6, s6)
        }
    };


    match is_plumbed_for_af(&ifname, sock) {
        true => {}
        false => {
            plumb_for_af(&ifname, iff)?;
        }
    };

    create_ip_addr(ifname, name.as_ref(), addr, sock)

}

fn is_plumbed_for_af(name: &str, sock: i32) -> bool {

    let mut req = crate::sys::lifreq::new();
    for (i, c) in name.chars().enumerate() {
        req.lifr_name[i] = c as i8
    }
    let ret = unsafe { ioctl(sock, sys::SIOCGLIFFLAGS, &req) };
    ret == 0

}

fn plumb_for_af(name: &str, ifflags: u32) -> Result<(), Error> {

    // TODO not handling interfaces assigned to different zones correctly.
    // TODO not handling loopback as special case like libipadm does

    let ip_h = dlpi::open(name, dlpi::sys::DLPI_NOATTACH)?;
    let ip_fd = match dlpi::fd(ip_h) {
        Ok(fd) => fd,
        Err(e) => {
            dlpi::close(ip_h);
            return Err(Error::Ioctl(
                    format!("DLPI IP fd: {}", e.to_string())
            ));
        }
    };

    // push ip module
    let ip_mod_name = CStr::from_bytes_with_nul(sys::IP_MOD_NAME).unwrap();
    match unsafe { ioctl(ip_fd, sys::I_PUSH, ip_mod_name.as_ptr()) } {
        -1 => {
            dlpi::close(ip_h);
            return Err(Error::Ioctl("IP streams push error".to_string()));
        }
        _ => {}
    }

    let spec = parse_ifspec(name);

    // create the new interface via SIOCSLIFNAME
    let mut req = sys::lifreq::new();
    req.lifr_lifru.lifru_flags = ifflags as u64;
    req.lifr_lifru1.lifru_ppa = spec.ppa;

    for (i, c) in name.chars().enumerate() {
        req.lifr_name[i] = c as i8;
    }
    match unsafe { ioctl(ip_fd, sys::SIOCSLIFNAME, &req) } {
        -1 => {
            dlpi::close(ip_h);
            return Err(Error::Ioctl(format!(
                "IP SIOCSLIFNAME, {}, {}", ip_fd, sys::errno_string(),
            )));
        }
        _ => {}
    }

    // get flags for the interface
    match unsafe { ioctl(ip_fd, sys::SIOCGLIFFLAGS, &req) } {
        -1 => {
            dlpi::close(ip_h);
            return Err(Error::Ioctl("IP SIOCGLIFNAME".to_string()));
        }
        _ => {}
    }
    
    let mux_fd = if (ifflags & sys::IFF_IPV6) != 0 {
        let dev = b"/dev/udp6\0";
        let devname = CStr::from_bytes_with_nul(dev).unwrap();
        unsafe { libc::open(devname.as_ptr(), libc::O_RDWR) }
    } else {
        let dev = b"/dev/udp\0";
        let devname = CStr::from_bytes_with_nul(dev).unwrap();
        unsafe { libc::open(devname.as_ptr(), libc::O_RDWR) }
    };


    // pop off unwanted modules
    loop {
        let res = unsafe { ioctl(mux_fd, sys::I_POP, 0) };
        if res == -1 {
            break;
        }
    }

    // push on arp module
    let arp_mod_name = CStr::from_bytes_with_nul(sys::ARP_MOD_NAME).unwrap();
    match unsafe { ioctl(mux_fd, sys::I_PUSH, arp_mod_name) } {
        -1 => {
            dlpi::close(ip_h);
            return Err(Error::Ioctl("ARP sterams push error".to_string()));
        }
        _ => {}
    }

    // check if ARP is not needed
    if (ifflags & (sys::IFF_NOARP | sys::IFF_IPV6)) != 0 {

        let ip_muxid = unsafe { ioctl(mux_fd, sys::I_PLINK, ip_fd) };
        if ip_muxid == -1 {
            dlpi::close(ip_h);
            unsafe { ioctl(mux_fd, sys::I_PUNLINK, ip_muxid) };
            return Err(Error::Ioctl(format!(
                "PLINK IP, {}, {}, {}", mux_fd, ip_fd, sys::errno_string(),
            )));
        }
        return Ok(())

    }

    // open arp dlpi
    let arp_h = match dlpi::open(name, dlpi::sys::DLPI_NOATTACH) {
        Ok(h) => h, 
        Err(e) => {
            dlpi::close(ip_h);
            return Err(Error::Ioctl(
                    format!("DLPI ARP open: {}", e.to_string())
            ));
        }
    };

    let arp_fd = match dlpi::fd(arp_h) {
        Ok(fd) => fd,
        Err(e) => {
            dlpi::close(ip_h);
            return Err(Error::Ioctl(
                    format!("DLPI ARP fd: {}", e.to_string())
            ));
        }
    };

    let arg = &mut req as *mut sys::lifreq as *mut c_char;
    let ret = str_ioctl(
        arp_fd, sys::SIOCSLIFNAME, arg, size_of::<sys::lifreq>() as c_int);
    if ret == -1 {
        dlpi::close(ip_h);
        dlpi::close(arp_h);
        return Err(Error::Ioctl("ARP SIOCSLIFNAME".to_string()));
    }

    // plink IP and arp streams

    let ip_muxid = unsafe { ioctl(mux_fd, sys::I_PLINK, ip_fd) };
    if ip_muxid == -1 {
        dlpi::close(ip_h);
        dlpi::close(arp_h);
        return Err(Error::Ioctl("PLINK ip_fd".to_string()));
    }

    let ret = unsafe { ioctl(mux_fd, sys::I_PLINK, arp_fd) };
    if ret == -1 {
        dlpi::close(ip_h);
        dlpi::close(arp_h);
        return Err(Error::Ioctl("PLINK arp_fd".to_string()));
    }

    dlpi::close(ip_h);
    dlpi::close(arp_h);
    Ok(())

    //TODO handle ndpd interactions :/

    
}

fn str_ioctl(s: c_int, cmd: c_int, buf: *mut c_char, buflen: c_int) -> c_int {

    let mut ioc = sys::strioctl::new();
    ioc.ic_cmd = cmd;
    ioc.ic_len = buflen;
    ioc.ic_dp = buf;

    unsafe { ioctl(s, sys::I_STR, &ioc) }

}

pub struct IfSpec {
    pub ppa: u32,
    pub lun: u32,
    pub lunvalid: bool,
    pub devnm: [u8; sys::LIFNAMSIZ],
}

/// Parse a interface specification with the following format.
///
///     <name>[ppa][:lun]
///
/// - name: name of the device
/// - ppa: physical point of attachment (integer)
/// - lun: logical unit numnber (integer)
fn parse_ifspec(ifname: &str) -> IfSpec {

    let parts: Vec::<&str> = ifname.split(":").collect();
    let (lun, lunvalid) = {
        match parts.len() {
            0 => (0, false),
            1 => (0, false),
            _ => {
                match u32::from_str_radix(parts[1], 10) {
                    Ok(i) => (i, true),
                    Err(_) => (0, false),
                }
            }
        }
    };
    let name = parts[0].trim_end_matches(char::is_numeric);
    let ppa = {
        let s = &parts[0][..name.len()];
        match u32::from_str_radix(s, 10) {
            Ok(i) => i,
            Err(_) => 0,
        }
    };

    let mut devnm = [0u8; sys::LIFNAMSIZ];
    for (i, c) in name.chars().enumerate() {
        devnm[i] = c as u8;
    }

    IfSpec{ ppa, lun, lunvalid, devnm }

}

pub fn get_ipaddr_info(name: &str) -> Result<IpInfo, Error> {

    unsafe {

        let (_, _, af, ifname, _) = crate::ip::addrobjname_to_addrobj(name)
            .map_err(|e| Error::Ioctl(
                    format!("get addrobj: {}", e.to_string())))?;

        let s4 = socket(AF_INET as i32, SOCK_DGRAM as i32, 0);
        if s4 < 0 {
            return Err(Error::Ioctl("socket 4".to_string()));
        }
        let s6 = socket(AF_INET6 as i32, SOCK_DGRAM as i32, 0);
        if s6 < 0 {
            close(s4);
            return Err(Error::Ioctl("socket 6".to_string()));
        }

        let ss = match af as i32 {
            AF_INET => s4,
            AF_INET6 => s6,
            _ => return Err(Error::Ioctl(
                    format!("unknown address family: {}", af))),
        };

        let mut req = sys::lifreq::new();
        for (i, c) in ifname.chars().enumerate() {
            req.lifr_name[i] = c as i8;
        }

        let lifc = sys::lifconf {
            lifc_family: af as u16,
            lifc_flags: (sys::LIFC_NOXMIT
                | sys::LIFC_TEMPORARY
                | sys::LIFC_ALLZONES
                | sys::LIFC_UNDER_IPMP) as i32,
                lifc_len: size_of::<sys::lifreq>() as i32,
                lifc_lifcu: sys::lifconf_lifcu {
                    lifcu_req: &mut req as *mut sys::lifreq,
                },
        };

        let ret = ioctl(ss, sys::SIOCGLIFCONF, &lifc);
        if ret != 0 {
            close(s4);
            close(s6);
            return Err(Error::Ioctl("ioctl SIOCGLIFCONF".to_string()));
        }


        ipaddr_info(&req, s4, s6)

    }

}

unsafe fn ipaddr_info(x: &sys::lifreq, s4: i32, s6: i32) -> Result<IpInfo, Error> {

    let _name = CStr::from_ptr(x.lifr_name.as_ptr());
    let name = match _name.to_str() {
        Ok(s) => s,
        Err(_) => {
            close(s4);
            close(s6);
            return Err(Error::Ioctl(
                    "interface name conversion".to_string()));
        }
    };

    let sa = x.lifr_lifru.lifru_addr;
    let addr = match sockaddr2ipaddr(&sa) {
        Some(addr) => addr,
        None => return Err(Error::Ioctl(
                "socaddr to ipaddr conversion".to_string())),
    };

    let ss = match sa.ss_family as i32 {
        AF_INET => s4,
        AF_INET6 => s6,
        _ => return Err(Error::Ioctl(
                "unknown address family".to_string())),
    };

    // get index
    let mut ret = ioctl(ss, sys::SIOCGLIFINDEX, x);
    if ret != 0 {
        close(s4);
        close(s6);
        return Err(Error::Ioctl("ioctl SIOCGLIFINDEX".to_string()));
    }
    let idx = x.lifr_lifru.lifru_index;

    // get netmask

    ret = ioctl(ss, sys::SIOCGLIFNETMASK, x);
    if ret != 0 {
        close(s4);
        close(s6);
        return Err(Error::Ioctl("ioctl SIOCGLIFNETMASK".to_string()));
    }
    let _mask = x.lifr_lifru.lifru_addr;
    let mask = match sockaddr2ipaddr(&_mask) {
        Some(mask) => mask,
        None => return Err(Error::Ioctl(
                "socaddr to ipaddr conversion".to_string())),
    };

    // determine state

    ret = ioctl(ss, sys::SIOCGLIFFLAGS, x);
    if ret != 0 {
        close(s4);
        close(s6);
        return Err(Error::Ioctl("ioctl SIOCGLIFFLAGS".to_string()));
    }
    let flags = x.lifr_lifru.lifru_flags;
    let state = {
        if flags & sys::IFF_UP as u64 != 0 {
            IpState::OK
        } else {
            if flags & sys::IFF_RUNNING as u64 != 0 {
                ret = ioctl(ss, sys::SIOCGLIFDADSTATE, x);
                if ret != 0 {
                    close(s4);
                    close(s6);
                    return Err(Error::Ioctl(
                            "ioctl SIOCGLIFFLAGS".to_string()));
                }

                if x.lifr_lifru.lifru_dadstate ==
                    sys::glif_dad_state_t_DAD_IN_PROGRESS {
                        IpState::Tentative
                    } else {
                        IpState::OK
                }
            } else {
                IpState::Inaccessible
            }
        }
    };

    Ok(IpInfo {
        ifname: name.to_string(),
        index: idx,
        addr: addr,
        mask: ip_mask(mask),
        family: sa.ss_family,
        state: state,
    })
}

//TODO check auth?
pub(crate) fn create_ip_addr(
    ifname: impl AsRef<str>,
    objname: impl AsRef<str>,
    addr: IpPrefix,
    sock: i32,
) -> Result<(), Error> {


    unsafe {

        let mut req: sys::lifreq = std::mem::zeroed();
        for (i,c) in ifname.as_ref().chars().enumerate() {
            req.lifr_name[i] = c as i8;
        }

        // create logical ip interface
        let ret = ioctl(sock,  sys::SIOCLIFADDIF, &req);
        if ret < 0 {
            return Err(Error::Ioctl(
                    format!("ioctl SIOCLIFADDIF: {}", sys::errno_string())))
        }

        let kernel_ifname = std::ffi::CStr::from_ptr(
            &mut req.lifr_name[0]).to_str()?;

        let parts: Vec<&str> = kernel_ifname.split(":").collect();
        let lifnum = match parts.len() {
            2 => {
                match i32::from_str_radix(parts[1], 10) {
                    Ok(n) => n,
                    Err(_) => 0,
                }
            }
            _ => 0,
        };

        // assign addr
        match addr {
            IpPrefix::V6(a) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET6 as u16;
                let sas = &mut req.lifr_lifru.lifru_addr as *mut sockaddr_storage;
                let sa6 = sas as *mut sockaddr_in6;
                (*sa6).sin6_addr.s6_addr = a.addr.octets();
            }
            IpPrefix::V4(_) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET as u16;
            }
        };
        let ret = ioctl(sock,  sys::SIOCSLIFADDR, &req);
        if ret < 0 {
            return Err(Error::Ioctl(
                    format!("ioctl SIOCSLIFADDR: {}", sys::errno_string())))
        }

        // assign netmask
        match addr {
            IpPrefix::V6(a) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET6 as u16;
                let sas = &mut req.lifr_lifru.lifru_addr as *mut sockaddr_storage;
                let sa6 = sas as *mut sockaddr_in6;
                let mut addr: u128 = 0;
                for i in 0..a.mask {
                    addr |= 1<<(127-i);
                }
                (*sa6).sin6_addr.s6_addr = Ipv6Addr::from(addr).octets();
            }
            IpPrefix::V4(_) => {
                req.lifr_lifru.lifru_addr.ss_family = AF_INET as u16;
            }
        };
        let ret = ioctl(sock,  sys::SIOCSLIFNETMASK, &req);
        if ret < 0 {
            return Err(Error::Ioctl(
                    format!("ioctl SIOCSLIFADDR: {}", sys::errno_string())))
        }

        // assign name
        let mut iaa: ip::IpmgmtAobjopArg = std::mem::zeroed();
        iaa.cmd = ip::IpmgmtCmd::AddrobjLookupAdd;
        for (i, c) in objname.as_ref().chars().enumerate() {
            iaa.objname[i] = c as i8;
        }
        for (i, c) in ifname.as_ref().chars().enumerate() {
            iaa.ifname[i] = c as i8;
        }
        iaa.family = match addr {
            IpPrefix::V6(_) => AF_INET6 as u16,
            IpPrefix::V4(_) => AF_INET as u16,
        };
        iaa.atype = ip::AddrType::Static;

        let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")?;

        let mut response: *mut ip::IpmgmtRval = malloc(std::mem::size_of::<
            ip::IpmgmtRval,
        >()) as *mut ip::IpmgmtRval;

        door_callp(f.as_raw_fd(), iaa, &mut response);
        free(response as *mut c_void);

        // set logical interface number
    
        iaa = std::mem::zeroed();
        iaa.cmd = ip::IpmgmtCmd::AddrobjSetLifnum;
        for (i, c) in objname.as_ref().chars().enumerate() {
            iaa.objname[i] = c as i8;
        }
        for (i, c) in ifname.as_ref().chars().enumerate() {
            iaa.ifname[i] = c as i8;
        }
        iaa.lnum = lifnum;
        let family = match addr {
            IpPrefix::V6(_) => AF_INET6 as u16,
            IpPrefix::V4(_) => AF_INET as u16,
        };
        iaa.family = family;
        iaa.atype = ip::AddrType::Static;

        let mut response: *mut ip::IpmgmtRval = malloc(std::mem::size_of::<
            ip::IpmgmtRval,
        >()) as *mut ip::IpmgmtRval;

        door_callp(f.as_raw_fd(), iaa, &mut response);
        free(response as *mut c_void);

        // set up
        
        let mut req: sys::lifreq = std::mem::zeroed();
        for (i,c) in kernel_ifname.chars().enumerate() {
            req.lifr_name[i] = c as i8;
        }
        req.lifr_lifru.lifru_flags |= sys::IFF_UP as u64;
        let ret = ioctl(sock, sys::SIOCSLIFFLAGS, &req);
        if ret < 0 {
            return Err(Error::Ioctl(
                    format!("ioctl SIOCSLIFFLAGS: {}", sys::errno_string())))
        }

        // persist.... kindof
        let mut nvl = nvpair::NvList::new_unique_names();
        nvl.insert("_ifname", ifname.as_ref())?;
        nvl.insert("_aobjname", objname.as_ref())?;
        nvl.insert("_lifnum", &(lifnum as i32))?;

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

        let nvl_c = nvl.as_mut_ptr();
        let mut nvl_buf: *mut c_char = std::ptr::null_mut();
        let mut nvl_sz: nvpair_sys::size_t = 0;
        let ret = nvpair_sys::nvlist_pack(
            nvl_c,
            &mut nvl_buf,
            &mut nvl_sz,
            nvpair_sys::NV_ENCODE_NATIVE,
            0,
        );
        if ret != 0 {
            return Err(Error::NvPair(format!("{}", ret)));
        }

        let arg = ip::IpmgmtSetAddr{
            cmd: ip::IpmgmtCmd::SetAddr,
            flags: sys::IPMGMT_ACTIVE,
            nvlsize: nvl_sz as u32,
        };

        let mut buf: Vec<c_char> = Vec::new();

        let arg_bytes = std::slice::from_raw_parts(
            (&arg as *const ip::IpmgmtSetAddr) as *const c_char,
            size_of::<ip::IpmgmtSetAddr>(),
        );
        for c in arg_bytes {
            buf.push(*c);
        }

        let nvl_bytes = std::slice::from_raw_parts(nvl_buf, nvl_sz as usize);
        for c in nvl_bytes {
            buf.push(*c);
        }

        let resp: ip::IpmgmtRval = door_call_slice(
            f.as_raw_fd(),
            buf.as_slice(),
        );
        if resp.err != 0 {
            return Err(Error::Ipmgmtd(format!("{}", sys::err_string(resp.err))));
        }

        //TODO duplicate address detection
        //let rtsock = socket(libc::AF_ROUTE, libc::SOCK_RAW, family as i32);

    };

    Ok(())

}

fn sockaddr2ipaddr(sa: &libc::sockaddr_storage) -> Option<IpAddr> {
    unsafe {
        match sa.ss_family as i32 {
            libc::AF_INET => {
                let sa4 = sa as *const sockaddr_storage as *const sockaddr_in;
                Some(IpAddr::V4(Ipv4Addr::from(
                            u32::from_be((*sa4).sin_addr.s_addr))))
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

pub(crate) fn create_vnic(id: u32, link_id: u32)
-> Result<crate::LinkInfo, Error> {
    unsafe {
        let fd = dld_fd()?;

        debug!("creating vnic with id {}", id);

        let mut arg = VnicIocCreate {
            vnic_id: id,
            link_id: link_id,
            mac_addr_type: VnicMacAddrType::Auto,
            mac_len: 0,
            mac_prefix_len: 3,
            mac_slot: -1,
            vid: 0,
            vrid: 0,
            af: AF_UNSPEC as i32,
            flags: 0,
            ..Default::default()
        };
        arg.mac_addr[0] = 0x02;
        arg.mac_addr[1] = 0x08;
        arg.mac_addr[2] = 0x20;

        sys::errno = 0;
        let ret = ioctl(fd.as_raw_fd(), sys::VNIC_IOC_CREATE, &arg);
        if ret < 0 {
            warn!("errno: {}", sys::errno);
            return Err(Error::Ioctl(format!("ioctl VNIC_IOC_CREATE {}", ret)));
        }

        Ok(crate::link::get_link(id)?)
    }
}

pub(crate) fn create_simnet(id: u32, flags: crate::LinkFlags)
-> Result<crate::LinkInfo, Error> {
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

        let ret = ioctl(fd.as_raw_fd(), sys::SIMNET_IOC_CREATE, &arg);
        if ret < 0 {
            return Err(Error::Ioctl(format!("ioctl SIMNET_IOC_CREATE {}", ret)));
        }
    }

    Ok(crate::link::get_link(id)?)
}

#[repr(C)]
pub struct SimnetIocDelete {
    link_id: u32,
    flags: u32,
}

#[repr(C)]
pub struct VnicIocDelete {
    link_id: u32,
}

pub(crate) fn delete_simnet(id: u32) -> Result<(), Error> {
    unsafe {
        let fd = dld_fd()?;
        let arg = SimnetIocDelete {
            link_id: id,
            flags: 0,
        };
        let ret = ioctl(fd.as_raw_fd(), sys::SIMNET_IOC_DELETE, &arg);
        if ret < 0 {
            return Err(Error::Ioctl(format!(
                "ioctl SIMNET_IOC_DELETE id={}: {}",
                id, ret
            )));
        }
    }
    Ok(())
}

pub(crate) fn delete_vnic(id: u32) -> Result<(), Error> {
    unsafe {
        let fd = dld_fd()?;
        let arg = VnicIocDelete { link_id: id };
        let ret = ioctl(fd.as_raw_fd(), sys::VNIC_IOC_DELETE, &arg);
        if ret < 0 {
            return Err(Error::Ioctl(format!(
                "ioctl VNIC_IOC_DELETE id={}: {}",
                id, ret
            )));
        }
    }
    Ok(())
}
