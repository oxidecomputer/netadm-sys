// Copyright 2021 Oxide Computer Company

use crate::sys::{
    self, close, dld_ioc_macaddrget_t, dld_macaddrinfo_t, ioctl, sockaddr_in, sockaddr_in6,
    sockaddr_storage, socket, AF_INET, AF_INET6, AF_UNSPEC, SOCK_DGRAM, __DLDIOC_MACADDRGET,
    __SIMNET_IOC_INFO, __SIMNET_IOC_MODIFY,
};
use crate::Error;
use crate::{IpInfo, IpState};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use tracing::{debug, warn};

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
        let ret = ioctl(fd.as_raw_fd(), __SIMNET_IOC_INFO, &arg);
        if ret != 0 {
            return Err(Error::Ioctl("ioctl SIMNET_IOC_INFO".to_string()));
        }
        Ok(arg)
    }
}

pub(crate) fn connect_simnet_peers(link_id: u32, peer_link_id: u32) -> Result<(), Error> {
    let fd = dld_fd()?;

    unsafe {
        let arg = SimnetModifyIoc {
            link_id: link_id,
            peer_link_id: peer_link_id,
            flags: 0,
        };
        let ret = ioctl(fd.as_raw_fd(), __SIMNET_IOC_MODIFY, &arg);
        if ret != 0 {
            return Err(Error::Ioctl("ioctl __SIMNET_IOC_MODIFY".to_string()));
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
        let ret = ioctl(fd.as_raw_fd(), sys::__VNIC_IOC_INFO, &arg);
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

        let ret = ioctl(fd.as_raw_fd(), __DLDIOC_MACADDRGET, &arg);
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
            lifn_family: sys::AF_UNSPEC as u16,
            lifn_flags: 0,
            lifn_count: 0,
        };

        let mut ret = ioctl(s4, sys::__SIOCGLIFNUM, &lifn);
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
                lifr_lifru1: sys::lifreq__bindgen_ty_1 { lifru_ppa: 0 },
                lifr_type: 0,
                lifr_lifru: sys::lifreq__bindgen_ty_2 { lifru_flags: 0 },
            },
        );

        let lifc = sys::lifconf {
            lifc_family: AF_UNSPEC as u16,
            lifc_flags: (sys::LIFC_NOXMIT
                | sys::LIFC_TEMPORARY
                | sys::LIFC_ALLZONES
                | sys::LIFC_UNDER_IPMP) as i32,
            lifc_len: lifn.lifn_count * size_of::<sys::lifreq>() as i32,
            lifc_lifcu: sys::lifconf__bindgen_ty_1 {
                lifcu_buf: ifs.as_mut_ptr() as *mut i8,
            },
        };

        ret = ioctl(s4, sys::__SIOCGLIFCONF, &lifc);
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
                    return Err(Error::Ioctl("interface name conversion".to_string()));
                }
            };

            let sa = x.lifr_lifru.lifru_addr;
            let addr = match sockaddr2ipaddr(&sa) {
                Some(addr) => addr,
                None => continue,
            };

            let ss = match sa.ss_family as u32 {
                sys::AF_INET => s4,
                sys::AF_INET6 => s6,
                _ => continue,
            };

            // get index
            ret = ioctl(ss, sys::__SIOCGLIFINDEX, x);
            if ret != 0 {
                close(s4);
                close(s6);
                return Err(Error::Ioctl("ioctl SIOCGLIFINDEX".to_string()));
            }
            let idx = x.lifr_lifru.lifru_index;

            // get netmask

            ret = ioctl(ss, sys::__SIOCGLIFNETMASK, x);
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

            ret = ioctl(ss, sys::__SIOCGLIFFLAGS, x);
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
                        ret = ioctl(ss, sys::__SIOCGLIFDADSTATE, x);
                        if ret != 0 {
                            close(s4);
                            close(s6);
                            return Err(Error::Ioctl("ioctl SIOCGLIFFLAGS".to_string()));
                        }

                        if x.lifr_lifru.lifru_dadstate == sys::glif_dad_state_t_DAD_IN_PROGRESS {
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

fn sockaddr2ipaddr(sa: &sys::sockaddr_storage) -> Option<IpAddr> {
    unsafe {
        match sa.ss_family as u32 {
            sys::AF_INET => {
                let sa4 = sa as *const sockaddr_storage as *const sockaddr_in;
                Some(IpAddr::V4(Ipv4Addr::new(
                    (*sa4).sin_addr.S_un.S_un_b.s_b1,
                    (*sa4).sin_addr.S_un.S_un_b.s_b2,
                    (*sa4).sin_addr.S_un.S_un_b.s_b3,
                    (*sa4).sin_addr.S_un.S_un_b.s_b4,
                )))
            }
            sys::AF_INET6 => {
                let sa6 = sa as *const sockaddr_storage as *const sockaddr_in6;
                let a6 = IpAddr::V6(Ipv6Addr::new(
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[0]),
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[1]),
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[2]),
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[3]),
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[4]),
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[5]),
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[6]),
                    u16::from_be((*sa6).sin6_addr._S6_un._S6_u16[7]),
                ));
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

pub(crate) fn create_vnic(id: u32, link_id: u32) -> Result<crate::LinkInfo, Error> {
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
            af: sys::AF_UNSPEC as i32,
            flags: 0,
            ..Default::default()
        };
        arg.mac_addr[0] = 0x02;
        arg.mac_addr[1] = 0x08;
        arg.mac_addr[2] = 0x20;

        sys::errno = 0;
        let ret = ioctl(fd.as_raw_fd(), sys::__VNIC_IOC_CREATE, &arg);
        if ret < 0 {
            warn!("errno: {}", sys::errno);
            return Err(Error::Ioctl(format!("ioctl VNIC_IOC_CREATE {}", ret)));
        }

        Ok(crate::link::get_link(id)?)
    }
}

pub(crate) fn create_simnet(id: u32, flags: crate::LinkFlags) -> Result<crate::LinkInfo, Error> {
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

        let ret = ioctl(fd.as_raw_fd(), sys::__SIMNET_IOC_CREATE, &arg);
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
        let ret = ioctl(fd.as_raw_fd(), sys::__SIMNET_IOC_DELETE, &arg);
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
        let ret = ioctl(fd.as_raw_fd(), sys::__VNIC_IOC_DELETE, &arg);
        if ret < 0 {
            return Err(Error::Ioctl(format!(
                "ioctl VNIC_IOC_DELETE id={}: {}",
                id, ret
            )));
        }
    }
    Ok(())
}
