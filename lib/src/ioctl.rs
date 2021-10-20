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
use crate::{Error, IpPrefix};
use crate::{IpInfo, IpState};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use tracing::{debug, warn};
use libc::{malloc, free};
use std::os::raw::{c_char, c_void};
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
            sys::lifreq {
                lifr_name: [0; 32usize],
                lifr_lifru1: sys::lifreq_ru1 { lifru_ppa: 0 },
                lifr_type: 0,
                lifr_lifru: sys::lifreq_ru { lifru_flags: 0 },
            },
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
                None => continue,
            };

            let ss = match sa.ss_family as i32 {
                AF_INET => s4,
                AF_INET6 => s6,
                _ => continue,
            };

            // get index
            ret = ioctl(ss, sys::SIOCGLIFINDEX, x);
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
                None => continue,
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

            let name_s = name.to_string();
            match result.get_mut(&name_s) {
                None => {
                    result.insert(
                        name_s,
                        vec![IpInfo {
                            ifname: name.to_string(),
                            index: idx,
                            addr: addr,
                            mask: ip_mask(mask),
                            family: sa.ss_family,
                            state: state,
                        }],
                    );
                }
                Some(v) => {
                    v.push(IpInfo {
                        ifname: name.to_string(),
                        index: idx,
                        addr: addr,
                        mask: ip_mask(mask),
                        family: sa.ss_family,
                        state: state,
                    });
                }
            }
        }

        close(s4);
        close(s6);
    }

    Ok(result)
}

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

    // delete the address
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

    unsafe{ close(sock) };

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

    let sock = match addr {
        IpPrefix::V4(_) => {
            let s4 = unsafe{ socket(AF_INET as i32, SOCK_DGRAM as i32, 0) };
            if s4 < 0 {
                return Err(Error::Ioctl("socket 4".to_string()));
            }
            s4
        }
        IpPrefix::V6(_) => {
            let s6 = unsafe{ socket(AF_INET6 as i32, SOCK_DGRAM as i32, 0) };
            if s6 < 0 {
                return Err(Error::Ioctl("socket 6".to_string()));
            }
            s6
        }
    };

    create_ip_addr(ifname, name.as_ref(), addr, sock)?;

    Ok(())

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

    }

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
