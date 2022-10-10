// Copyright 2021 Oxide Computer Company

// For the moment, the code in this file stylistically follows c conventions
// more than rust, for this reason the following warnings are disabled.
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]
#![allow(deref_nullptr)]
#![allow(unaligned_references)]

use libc::{in6_addr, sockaddr_in6, sockaddr_storage};

use std::os::raw::{
    c_char, c_int, c_longlong, c_uchar, c_uint, c_ulong, c_ulonglong, c_ushort,
};

pub type id_t = c_int;
pub type uint_t = c_uint;
pub type zoneid_t = id_t;
pub type caddr_t = *mut c_char;
pub type uchar_t = c_uchar;
pub type ushort_t = c_ushort;
pub type pid_t = c_int;
pub type kid_t = c_int;
pub type size_t = ulong_t;
pub type longlong_t = c_longlong;
pub type hrtime_t = longlong_t;
pub type u_longlong_t = c_ulonglong;
pub type ulong_t = c_ulong;

pub const boolean_t_B_FALSE: boolean_t = 0;
pub const boolean_t_B_TRUE: boolean_t = 1;
pub type boolean_t = c_uint;

pub const MAXMACADDRLEN: u32 = 20;
pub const MAXPATHLEN: u32 = 1024;
pub const MAXNAMELEN: u32 = 256;
pub const MAXLINKNAMELEN: u32 = 32;

pub const LIFC_NOXMIT: u32 = 1;
pub const LIFC_EXTERNAL_SOURCE: u32 = 2;
pub const LIFC_TEMPORARY: u32 = 4;
pub const LIFC_ALLZONES: u32 = 8;
pub const LIFC_UNDER_IPMP: u32 = 16;
pub const LIFC_ENABLED: u32 = 32;

#[cfg(target_os = "linux")]
type ioc_t = u64;
#[cfg(target_os = "illumos")]
type ioc_t = i32;

pub const DLD_IOC: ioc_t = 0x0D1D;
pub const AGGR_IOC: ioc_t = 0x0A66;
pub const VNIC_IOC: ioc_t = 0x0171;
pub const SIMNET_IOC: ioc_t = 0x5132;
pub const IPTUN_IOC: ioc_t = 0x454A;
pub const BRIDGE_IOC: ioc_t = 0xB81D;
pub const IBPART_IOC: ioc_t = 0x6171;

pub const IOCPARM_MASK: u32 = 0xff;
pub const IOC_OUT: u32 = 0x40000000;
pub const IOC_IN: u32 = 0x80000000;
pub const IOC_INOUT: u32 = IOC_OUT | IOC_IN;

pub const STR: ioc_t = ('S' as ioc_t) << 8;
pub const I_PUSH: ioc_t = STR | 0o2;
pub const I_POP: ioc_t = STR | 0o3;
pub const I_PLINK: ioc_t = STR | 0o26;
pub const I_PUNLINK: ioc_t = STR | 0o27;
pub const I_STR: ioc_t = STR | 0o10;

pub const IP_MOD_NAME: &[u8; 3] = b"ip\0";
pub const ARP_MOD_NAME: &[u8; 4] = b"arp\0";

pub type nvlist_t = nvlist;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nvlist {
    pub nvl_version: i32,
    pub nvl_nvflag: u32,
    pub nvl_priv: u64,
    pub nvl_flag: u32,
    pub nvl_pad: i32,
}

macro_rules! DLD_IOC_CMD {
    ($modid:expr, $cmdid:expr) => {
        ($modid << 16) | $cmdid
    };
}

macro_rules! DLDIOC {
    ($cmdid:expr) => {
        DLD_IOC_CMD!(DLD_IOC, $cmdid)
    };
}

macro_rules! IOW {
    ($x:expr, $y:expr, $t:ty) => {
        IOC_IN
            | (std::mem::size_of::<$t>() as u32 & IOCPARM_MASK) << 16
            | ($x as u32) << 8
            | $y
    };
}

macro_rules! IOWR {
    ($x:expr, $y:expr, $t:ty) => {
        IOC_INOUT
            | (std::mem::size_of::<$t>() as u32 & IOCPARM_MASK) << 16
            | ($x as u32) << 8
            | $y
    };
}

macro_rules! IOWRN {
    ($x:expr, $y:expr, $t:expr) => {
        IOC_INOUT | ($t & IOCPARM_MASK) << 16 | ($x as u32) << 8 | $y
    };
}

pub type sa_family_t = u16;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lifnum {
    pub lifn_family: sa_family_t,
    pub lifn_flags: ::std::os::raw::c_int,
    pub lifn_count: ::std::os::raw::c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct lifreq {
    pub lifr_name: [::std::os::raw::c_char; 32usize],
    pub lifr_lifru1: lifreq_ru1,
    pub lifr_type: uint_t,
    pub lifr_lifru: lifreq_ru,
}

impl lifreq {
    pub fn new() -> Self {
        lifreq {
            lifr_name: [0; 32usize],
            lifr_lifru1: lifreq_ru1 { lifru_ppa: 0 },
            lifr_type: 0,
            lifr_lifru: lifreq_ru { lifru_flags: 0 },
        }
    }
}

impl Default for lifreq {
    fn default() -> lifreq {
        lifreq {
            lifr_name: [0; 32usize],
            lifr_lifru1: lifreq_ru1 { lifru_ppa: 0 },
            lifr_type: 0,
            lifr_lifru: lifreq_ru { lifru_flags: 0 },
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union lifreq_ru1 {
    pub lifru_addrlen: ::std::os::raw::c_int,
    pub lifru_ppa: uint_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union lifreq_ru {
    pub lifru_addr: sockaddr_storage,
    pub lifru_dstaddr: sockaddr_storage,
    pub lifru_broadaddr: sockaddr_storage,
    pub lifru_token: sockaddr_storage,
    pub lifru_subnet: sockaddr_storage,
    pub lifru_index: ::std::os::raw::c_int,
    pub lifru_flags: u64,
    pub lifru_metric: ::std::os::raw::c_int,
    pub lifru_mtu: uint_t,
    pub lif_muxid: [::std::os::raw::c_int; 2usize],
    pub lifru_nd_req: lif_nd_req,
    pub lifru_ifinfo_req: lif_ifinfo_req,
    pub lifru_groupname: [::std::os::raw::c_char; 32usize],
    pub lifru_binding: [::std::os::raw::c_char; 32usize],
    pub lifru_zoneid: zoneid_t,
    pub lifru_dadstate: uint_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct lifconf {
    pub lifc_family: sa_family_t,
    pub lifc_flags: ::std::os::raw::c_int,
    pub lifc_len: ::std::os::raw::c_int,
    pub lifc_lifcu: lifconf_lifcu,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union lifconf_lifcu {
    pub lifcu_buf: caddr_t,
    pub lifcu_req: *mut lifreq,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lif_ifinfo_req {
    pub lir_maxhops: u8,
    pub lir_reachtime: u32,
    pub lir_reachretrans: u32,
    pub lir_maxmtu: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct lif_nd_req {
    pub lnr_addr: sockaddr_storage,
    pub lnr_state_create: u8,
    pub lnr_state_same_lla: u8,
    pub lnr_state_diff_lla: u8,
    pub lnr_hdw_len: ::std::os::raw::c_int,
    pub lnr_flags: ::std::os::raw::c_int,
    pub lnr_pad0: ::std::os::raw::c_int,
    pub lnr_hdw_addr: [::std::os::raw::c_char; 64usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct strioctl {
    pub ic_cmd: c_int,
    pub ic_timeout: c_int,
    pub ic_len: c_int,
    pub ic_dp: *mut c_char,
}

impl strioctl {
    pub fn new() -> Self {
        strioctl {
            ic_cmd: 0,
            ic_timeout: 0,
            ic_len: 0,
            ic_dp: std::ptr::null_mut::<c_char>(),
        }
    }
}

impl Default for strioctl {
    fn default() -> Self {
        Self::new()
    }
}

pub const LIFNAMSIZ: usize = 32;
pub const ND_MAX_HDW_LEN: usize = 64;

pub const DLDIOC_MACADDRGET: ioc_t = DLDIOC!(0x15);
pub const SIOCLIFREMOVEIF: ioc_t = IOW!('i', 110, lifreq) as ioc_t;
pub const SIOCLIFADDIF: ioc_t = IOWR!('i', 111, lifreq) as ioc_t;
pub const SIOCSLIFADDR: ioc_t = IOW!('i', 112, lifreq) as ioc_t;
pub const SIOCGLIFADDR: ioc_t = IOWR!('i', 113, lifreq) as ioc_t;
pub const SIOCSLIFFLAGS: ioc_t = IOW!('i', 116, lifreq) as ioc_t;
pub const SIOCGLIFFLAGS: ioc_t = IOWR!('i', 117, lifreq) as ioc_t;
pub const SIOCGLIFNETMASK: ioc_t = IOWR!('i', 125, lifreq) as ioc_t;
pub const SIOCSLIFNETMASK: ioc_t = IOW!('i', 126, lifreq) as ioc_t;
pub const SIOCSLIFNAME: ioc_t = IOWR!('i', 129, lifreq) as ioc_t;
pub const SIOCGLIFNUM: ioc_t = IOWR!('i', 130, lifnum) as ioc_t;
pub const SIOCGLIFINDEX: ioc_t = IOWR!('i', 133, lifreq) as ioc_t;
pub const SIOCGLIFCONF: ioc_t = IOWRN!('i', 165, 16) as ioc_t;
pub const SIOCGLIFDADSTATE: ioc_t = IOWR!('i', 190, lifreq) as ioc_t;
pub const SIOCSLIFPREFIX: ioc_t = IOWR!('i', 191, lifreq) as ioc_t;
pub const SIOCGNDNUM: ioc_t = IOWR!('i', 193, ndpreq) as ioc_t;
pub const SIOCGNDS: ioc_t = IOWR!('i', 194, ndpreq) as ioc_t;

macro_rules! SIMNETIOC {
    ($cmdid:expr) => {
        DLD_IOC_CMD!(SIMNET_IOC, $cmdid)
    };
}
pub const SIMNET_IOC_CREATE: ioc_t = SIMNETIOC!(1);
pub const SIMNET_IOC_DELETE: ioc_t = SIMNETIOC!(2);
pub const SIMNET_IOC_INFO: ioc_t = SIMNETIOC!(3);
pub const SIMNET_IOC_MODIFY: ioc_t = SIMNETIOC!(4);

macro_rules! VNICIOC {
    ($cmdid:expr) => {
        DLD_IOC_CMD!(VNIC_IOC, $cmdid)
    };
}
pub const VNIC_IOC_CREATE: ioc_t = VNICIOC!(1);
pub const VNIC_IOC_DELETE: ioc_t = VNICIOC!(2);
pub const VNIC_IOC_INFO: ioc_t = VNICIOC!(3);
pub const VNIC_IOC_MODIFY: ioc_t = VNICIOC!(4);

//TODO work to get ipmgmt types exported by illumos, but not with ipadm types in
//the mix, this will require some work on the ipmgmt data structures to
//eradicate dladm types

//XXX dupe with crate::ip::IpmgmtAddrObjRval
pub type ipmgmt_aobjop_rval_t = ipmgmt_aobjop_rval_s;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ipmgmt_aobjop_rval_s {
    pub ir_err: i32,
    pub ir_aobjname: [::std::os::raw::c_char; 64usize],
    pub ir_ifname: [::std::os::raw::c_char; 32usize],
    pub ir_lnum: i32,
    pub ir_family: sa_family_t,
    pub ir_flags: u32,
    pub ir_atype: ipadm_addr_type_t,
    pub ir_atype_cache: ipmgmt_addr_type_cache_u,
}

pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_SETPROP: ipmgmt_door_cmd_type_t = 1;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_SETIF: ipmgmt_door_cmd_type_t = 2;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_SETADDR: ipmgmt_door_cmd_type_t = 3;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_GETPROP: ipmgmt_door_cmd_type_t = 4;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_GETIF: ipmgmt_door_cmd_type_t = 5;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_GETADDR: ipmgmt_door_cmd_type_t = 6;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_RESETIF: ipmgmt_door_cmd_type_t = 7;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_RESETADDR: ipmgmt_door_cmd_type_t =
    8;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_RESETPROP: ipmgmt_door_cmd_type_t =
    9;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_INITIF: ipmgmt_door_cmd_type_t = 10;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_ADDROBJ_LOOKUPADD:
    ipmgmt_door_cmd_type_t = 11;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_ADDROBJ_SETLIFNUM:
    ipmgmt_door_cmd_type_t = 12;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_ADDROBJ_ADD:
    ipmgmt_door_cmd_type_t = 13;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_LIF2ADDROBJ:
    ipmgmt_door_cmd_type_t = 14;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_AOBJNAME2ADDROBJ:
    ipmgmt_door_cmd_type_t = 15;
pub type ipmgmt_door_cmd_type_t = ::std::os::raw::c_uint;

#[repr(C)]
#[derive(Copy, Clone)]
pub union ipmgmt_addr_type_cache_u {
    pub ipmgmt_ipv6_cache_s: ipmgmt_addr_type_cache_ipv6,
    pub ipmgmt_dhcp_cache_s: ipmgmt_addr_type_cache_dhcp,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ipmgmt_addr_type_cache_ipv6 {
    pub ipmgmt_linklocal: boolean_t,
    pub ipmgmt_ifid: sockaddr_in6,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipmgmt_addr_type_cache_dhcp {
    pub ipmgmt_reqhost: [::std::os::raw::c_char; 256usize],
}

pub type ipmgmt_aobjop_arg_t = ipmgmt_aobjop_arg_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipmgmt_aobjop_arg_s {
    pub ia_cmd: ipmgmt_door_cmd_type_t,
    pub ia_flags: u32,
    pub ia_aobjname: [::std::os::raw::c_char; 64usize],
    pub ia_ifname: [::std::os::raw::c_char; 32usize],
    pub ia_lnum: i32,
    pub ia_family: sa_family_t,
    pub ia_atype: ipadm_addr_type_t,
}

//TODO no ipadm types

pub type ipadm_dbwrite_cbarg_t = ipadm_dbwrite_cbarg_s;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipadm_dbwrite_cbarg_s {
    pub dbw_nvl: *mut nvlist_t,
    pub dbw_flags: uint_t,
}

pub type ipadm_if_info_t = ipadm_if_info_s;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipadm_if_info_list_s {
    pub ifil_next: *mut ipadm_if_info_list_s,
    pub ifil_ifi: ipadm_if_info_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipadm_if_info_s {
    pub ifi_name: [::std::os::raw::c_char; 32usize],
    pub ifi_state: ipadm_if_state_t,
    pub ifi_cflags: uint_t,
    pub ifi_pflags: uint_t,
}

pub const ipadm_if_state_t_IFIS_OK: ipadm_if_state_t = 0;
pub const ipadm_if_state_t_IFIS_DOWN: ipadm_if_state_t = 1;
pub const ipadm_if_state_t_IFIS_FAILED: ipadm_if_state_t = 2;
pub const ipadm_if_state_t_IFIS_OFFLINE: ipadm_if_state_t = 3;
pub const ipadm_if_state_t_IFIS_DISABLED: ipadm_if_state_t = 4;
pub type ipadm_if_state_t = ::std::os::raw::c_uint;

pub type ipadm_if_info_list_t = ipadm_if_info_list_s;
pub const ipadm_addr_state_t_IFA_DISABLED: ipadm_addr_state_t = 0;
pub const ipadm_addr_state_t_IFA_DUPLICATE: ipadm_addr_state_t = 1;
pub const ipadm_addr_state_t_IFA_DOWN: ipadm_addr_state_t = 2;
pub const ipadm_addr_state_t_IFA_TENTATIVE: ipadm_addr_state_t = 3;
pub const ipadm_addr_state_t_IFA_OK: ipadm_addr_state_t = 4;
pub const ipadm_addr_state_t_IFA_INACCESSIBLE: ipadm_addr_state_t = 5;
pub type ipadm_addr_state_t = ::std::os::raw::c_uint;
pub const ipadm_addr_type_t_IPADM_ADDR_NONE: ipadm_addr_type_t = 0;
pub const ipadm_addr_type_t_IPADM_ADDR_STATIC: ipadm_addr_type_t = 1;
pub const ipadm_addr_type_t_IPADM_ADDR_IPV6_ADDRCONF: ipadm_addr_type_t = 2;
pub const ipadm_addr_type_t_IPADM_ADDR_DHCP: ipadm_addr_type_t = 3;
pub type ipadm_addr_type_t = ::std::os::raw::c_uint;

pub type datalink_id_t = u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dld_ioc_macaddrget {
    pub dig_linkid: datalink_id_t,
    pub dig_count: uint_t,
    pub dig_size: uint_t,
}
pub type dld_ioc_macaddrget_t = dld_ioc_macaddrget;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct dld_macaddrinfo {
    pub dmi_slot: uint_t,
    pub dmi_flags: uint_t,
    pub dmi_addrlen: uint_t,
    pub dmi_addr: [uchar_t; 20usize],
    pub dmi_client_name: [::std::os::raw::c_char; 256usize],
    pub dma_client_linkid: datalink_id_t,
}
pub type dld_macaddrinfo_t = dld_macaddrinfo;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rt_metrics {
    pub locks: u32,    /* Kernel must leave  these  values alone */
    pub mtu: u32,      /* MTU for this path */
    pub hopcount: u32, /* max hops expected */
    pub expire: u32,   /* lifetime for route, e.g., redirect */
    pub recvpipe: u32, /* inbound delay-bandwidth  product */
    pub sendpipe: u32, /* outbound delay-bandwidth product */
    pub ssthresh: u32, /* outbound gateway buffer limit */
    pub rtt: u32,      /* estimated round trip time */
    pub rttvar: u32,   /* estimated rtt variance */
    pub pksent: u32,   /* packets sent using this route */
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rt_msghdr {
    pub msglen: ushort_t, /* to skip over non-understood messages */
    pub version: uchar_t, /* future binary compatibility */
    pub typ: uchar_t,     /* message type */
    pub index: ushort_t,  /* index for associated ifp */
    pub flags: c_int,     /* flags,  incl  kern  &  message, e.g., DONE */
    pub addrs: c_int,     /* bitmask identifying sockaddrs in msg */
    pub pid: pid_t,       /* identify sender */
    pub seq: c_int,       /* for sender to identify action */
    pub errno: c_int,     /* why failed */
    pub used: c_int,      /* from rtentry */
    pub inits: uint_t,    /* which values we are initializing */
    pub rmx: rt_metrics,  /* metrics themselves */
}

impl Default for rt_msghdr {
    fn default() -> Self {
        unsafe {
            rt_msghdr {
                msglen: std::mem::size_of::<rt_msghdr>() as u16,
                version: RTM_VERSION as u8,
                typ: RTM_GETALL as u8,
                addrs: 0,
                pid: getpid(),
                seq: 1701,
                errno: 0,
                flags: 0,
                used: 0,
                inits: 0,
                index: 0,
                rmx: rt_metrics {
                    locks: 0,
                    mtu: 0,
                    hopcount: 0,
                    expire: 0,
                    recvpipe: 0,
                    sendpipe: 0,
                    ssthresh: 0,
                    rtt: 0,
                    rttvar: 0,
                    pksent: 0,
                },
            }
        }
    }
}

impl Default for ipmgmt_aobjop_rval_t {
    fn default() -> Self {
        ipmgmt_aobjop_rval_t {
            ir_err: 0,
            ir_aobjname: [0; 64usize],
            ir_ifname: [0; 32usize],
            ir_lnum: 0,
            ir_family: 0,
            ir_flags: 0,
            ir_atype: 0,
            ir_atype_cache: ipmgmt_addr_type_cache_u {
                ipmgmt_ipv6_cache_s: ipmgmt_addr_type_cache_ipv6 {
                    ipmgmt_linklocal: 0,
                    ipmgmt_ifid: sockaddr_in6 {
                        sin6_family: 0,
                        sin6_port: 0,
                        sin6_flowinfo: 0,
                        sin6_addr: in6_addr { s6_addr: [0; 16] },
                        sin6_scope_id: 0,
                        ..unsafe { std::mem::zeroed() }
                    },
                },
            },
        }
    }
}

pub const IFF_UP: u32 = 1;
pub const IFF_BROADCAST: u32 = 2;
pub const IFF_DEBUG: u32 = 4;
pub const IFF_LOOPBACK: u32 = 8;
pub const IFF_POINTOPOINT: u32 = 16;
pub const IFF_NOTRAILERS: u32 = 32;
pub const IFF_RUNNING: u32 = 64;
pub const IFF_NOARP: u32 = 128;
pub const IFF_PROMISC: u32 = 256;
pub const IFF_ALLMULTI: u32 = 512;
pub const IFF_INTELLIGENT: u32 = 1024;
pub const IFF_MULTICAST: u32 = 2048;
pub const IFF_MULTI_BCAST: u32 = 4096;
pub const IFF_UNNUMBERED: u32 = 8192;
pub const IFF_DHCPRUNNING: u32 = 16384;
pub const IFF_PRIVATE: u32 = 32768;
pub const IFF_NOXMIT: u32 = 65536;
pub const IFF_NOLOCAL: u32 = 131072;
pub const IFF_DEPRECATED: u32 = 262144;
pub const IFF_ADDRCONF: u32 = 524288;
pub const IFF_ROUTER: u32 = 1048576;
pub const IFF_NONUD: u32 = 2097152;
pub const IFF_ANYCAST: u32 = 4194304;
pub const IFF_NORTEXCH: u32 = 8388608;
pub const IFF_IPV4: u32 = 16777216;
pub const IFF_IPV6: u32 = 33554432;
pub const IFF_NOACCEPT: u32 = 67108864;
pub const IFF_NOFAILOVER: u32 = 134217728;
pub const IFF_FAILED: u32 = 268435456;
pub const IFF_STANDBY: u32 = 536870912;
pub const IFF_INACTIVE: u32 = 1073741824;
pub const IFF_OFFLINE: u32 = 2147483648;
pub const IFF_XRESOLV: u64 = 4294967296;
pub const IFF_COS_ENABLED: u64 = 8589934592;
pub const IFF_PREFERRED: u64 = 17179869184;
pub const IFF_TEMPORARY: u64 = 34359738368;
pub const IFF_FIXEDMTU: u64 = 68719476736;
pub const IFF_VIRTUAL: u64 = 137438953472;
pub const IFF_DUPLICATE: u64 = 274877906944;
pub const IFF_IPMP: u64 = 549755813888;
pub const IFF_VRRP: u64 = 1099511627776;
pub const IFF_NOLINKLOCAL: u64 = 2199023255552;
pub const IFF_L3PROTECT: u64 = 4398046511104;
pub const IFF_CANTCHANGE: u64 = 8736013826906;
pub const IFF_IPMP_CANTCHANGE: u32 = 268435456;
pub const IFF_IPMP_INVALID: u64 = 8256487552;

pub const IPMGMT_APPEND: u32 = 0x00000001;
pub const IPMGMT_REMOVE: u32 = 0x00000002;
pub const IPMGMT_ACTIVE: u32 = 0x00000004;
pub const IPMGMT_PERSIST: u32 = 0x00000008;
pub const IPMGMT_INIT: u32 = 0x00000010;
pub const IPMGMT_PROPS_ONLY: u32 = 0x00000020;
pub const IPMGMT_UPDATE_IF: u32 = 0x00000040;
pub const IPMGMT_UPDATE_IPMP: u32 = 0x00000080;

fn errno_ptr() -> *mut c_int {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "illumos")] {
            unsafe { libc::___errno() }
        } else if #[cfg(target_os = "linux")] {
            unsafe { libc::__errno_location() }
        } else {
            compile_fail!("only linux and illumos are currently supported")
        }
    }
}

pub fn errno() -> c_int {
    unsafe { *errno_ptr() }
}

pub fn clear_errno() {
    unsafe {
        *errno_ptr() = 0;
    }
}

pub fn errno_string() -> String {
    err_string(errno())
}

pub fn err_string(err: i32) -> String {
    // We could attempt to grow `buf` if we get back `ERANGE`, but (a) 128 bytes
    // is probably more than enought and (b) if we fail we have a fallback plan
    // anyway.
    let mut buf = [0; 128];
    let ret = unsafe { libc::strerror_r(err, buf.as_mut_ptr(), buf.len()) };
    if ret == 0 {
        // TODO-cleanup We could use `CStr::from_bytes_until_nul()` to avoid
        // this `unsafe` block once it's stabilized. For now, `buf` contains
        // many nul bytes (after the one added by `strerror_r`, so we'll use
        // `CStr::from_ptr()` to search for the first nul.
        let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        if let Ok(s) = cstr.to_str() {
            return s.to_string();
        }
    }

    // Either `strerror_r` or conversion to a a UTF8 string failed; fall back
    // to a message that just includes the error number
    format!("unknown failure (errno {})", err)
}

pub type kstat_ctl_t = kstat_ctl;
extern "C" {
    pub fn kstat_open() -> *mut kstat_ctl_t;
    pub fn kstat_lookup(
        arg1: *mut kstat_ctl_t,
        arg2: *mut ::std::os::raw::c_char,
        arg3: ::std::os::raw::c_int,
        arg4: *mut ::std::os::raw::c_char,
    ) -> *mut kstat_t;
    pub fn kstat_close(arg1: *mut kstat_ctl_t) -> ::std::os::raw::c_int;
    pub fn kstat_read(
        arg1: *mut kstat_ctl_t,
        arg2: *mut kstat_t,
        arg3: *mut ::std::os::raw::c_void,
    ) -> kid_t;
    pub fn kstat_write(
        arg1: *mut kstat_ctl_t,
        arg2: *mut kstat_t,
        arg3: *mut ::std::os::raw::c_void,
    ) -> kid_t;
    pub fn kstat_data_lookup(
        arg1: *mut kstat_t,
        arg2: *mut ::std::os::raw::c_char,
    ) -> *mut ::std::os::raw::c_void;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kstat_ctl {
    pub kc_chain_id: kid_t,
    pub kc_chain: *mut kstat_t,
    pub kc_kd: ::std::os::raw::c_int,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kstat {
    pub ks_crtime: hrtime_t,
    pub ks_next: *mut kstat,
    pub ks_kid: kid_t,
    pub ks_module: [::std::os::raw::c_char; 31usize],
    pub ks_resv: uchar_t,
    pub ks_instance: ::std::os::raw::c_int,
    pub ks_name: [::std::os::raw::c_char; 31usize],
    pub ks_type: uchar_t,
    pub ks_class: [::std::os::raw::c_char; 31usize],
    pub ks_flags: uchar_t,
    pub ks_data: *mut ::std::os::raw::c_void,
    pub ks_ndata: uint_t,
    pub ks_data_size: size_t,
    pub ks_snaptime: hrtime_t,
    pub ks_update: ::std::option::Option<
        unsafe extern "C" fn(
            arg1: *mut kstat,
            arg2: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int,
    >,
    pub ks_private: *mut ::std::os::raw::c_void,
    pub ks_snapshot: ::std::option::Option<
        unsafe extern "C" fn(
            arg1: *mut kstat,
            arg2: *mut ::std::os::raw::c_void,
            arg3: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int,
    >,
    pub ks_lock: *mut ::std::os::raw::c_void,
}
pub type kstat_t = kstat;

pub const glif_dad_state_t_DAD_IN_PROGRESS: glif_dad_state_t = 1;
pub const glif_dad_state_t_DAD_DONE: glif_dad_state_t = 2;
pub type glif_dad_state_t = ::std::os::raw::c_uint;

pub const DL_CSMACD: u32 = 0;
pub const DL_TPB: u32 = 1;
pub const DL_TPR: u32 = 2;
pub const DL_METRO: u32 = 3;
pub const DL_ETHER: u32 = 4;
pub const DL_HDLC: u32 = 5;
pub const DL_CHAR: u32 = 6;
pub const DL_CTCA: u32 = 7;
pub const DL_FDDI: u32 = 8;
pub const DL_FC: u32 = 16;
pub const DL_ATM: u32 = 17;
pub const DL_IPATM: u32 = 18;
pub const DL_X25: u32 = 19;
pub const DL_ISDN: u32 = 20;
pub const DL_HIPPI: u32 = 21;
pub const DL_100VG: u32 = 22;
pub const DL_100VGTPR: u32 = 23;
pub const DL_ETH_CSMA: u32 = 24;
pub const DL_100BT: u32 = 25;
pub const DL_IB: u32 = 26;
pub const DL_FRAME: u32 = 10;
pub const DL_MPFRAME: u32 = 11;
pub const DL_ASYNC: u32 = 12;
pub const DL_IPX25: u32 = 13;
pub const DL_LOOP: u32 = 14;
pub const DL_OTHER: u32 = 9;

pub const link_state_t_LINK_STATE_UNKNOWN: link_state_t = -1;
pub const link_state_t_LINK_STATE_DOWN: link_state_t = 0;
pub const link_state_t_LINK_STATE_UP: link_state_t = 1;
pub type link_state_t = ::std::os::raw::c_int;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct kstat_named {
    pub name: [::std::os::raw::c_char; 31usize],
    pub data_type: uchar_t,
    pub value: kstat_named_value,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union kstat_named_value {
    pub c: [::std::os::raw::c_char; 16usize],
    pub i32_: i32,
    pub ui32: u32,
    pub str_: kstat_named_value_str,
    pub i64_: i64,
    pub ui64: u64,
    pub l: ::std::os::raw::c_long,
    pub ul: ulong_t,
    pub ll: longlong_t,
    pub ull: u_longlong_t,
    pub f: f32,
    pub d: f64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct kstat_named_value_str {
    pub addr: kstat_named_value_str_addr,
    pub len: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union kstat_named_value_str_addr {
    pub ptr: *mut ::std::os::raw::c_char,
    pub __pad: [::std::os::raw::c_char; 8usize],
}

pub type kstat_named_t = kstat_named;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct vopstats {
    pub nopen: kstat_named_t,
    pub nclose: kstat_named_t,
    pub nread: kstat_named_t,
    pub read_bytes: kstat_named_t,
    pub nwrite: kstat_named_t,
    pub write_bytes: kstat_named_t,
    pub nioctl: kstat_named_t,
    pub nsetfl: kstat_named_t,
    pub ngetattr: kstat_named_t,
    pub nsetattr: kstat_named_t,
    pub naccess: kstat_named_t,
    pub nlookup: kstat_named_t,
    pub ncreate: kstat_named_t,
    pub nremove: kstat_named_t,
    pub nlink: kstat_named_t,
    pub nrename: kstat_named_t,
    pub nmkdir: kstat_named_t,
    pub nrmdir: kstat_named_t,
    pub nreaddir: kstat_named_t,
    pub readdir_bytes: kstat_named_t,
    pub nsymlink: kstat_named_t,
    pub nreadlink: kstat_named_t,
    pub nfsync: kstat_named_t,
    pub ninactive: kstat_named_t,
    pub nfid: kstat_named_t,
    pub nrwlock: kstat_named_t,
    pub nrwunlock: kstat_named_t,
    pub nseek: kstat_named_t,
    pub ncmp: kstat_named_t,
    pub nfrlock: kstat_named_t,
    pub nspace: kstat_named_t,
    pub nrealvp: kstat_named_t,
    pub ngetpage: kstat_named_t,
    pub nputpage: kstat_named_t,
    pub nmap: kstat_named_t,
    pub naddmap: kstat_named_t,
    pub ndelmap: kstat_named_t,
    pub npoll: kstat_named_t,
    pub ndump: kstat_named_t,
    pub npathconf: kstat_named_t,
    pub npageio: kstat_named_t,
    pub ndumpctl: kstat_named_t,
    pub ndispose: kstat_named_t,
    pub nsetsecattr: kstat_named_t,
    pub ngetsecattr: kstat_named_t,
    pub nshrlock: kstat_named_t,
    pub nvnevent: kstat_named_t,
    pub nreqzcbuf: kstat_named_t,
    pub nretzcbuf: kstat_named_t,
}

pub const ND_UNCHANGED: u16 = 0; /* For ioctls that don't modify state */
pub const ND_INCOMPLETE: u16 = 1; /* addr resolution in progress */
pub const ND_REACHABLE: u16 = 2; /* have recently been reachable */
pub const ND_STALE: u16 = 3; /* may be unreachable, don't do anything */
pub const ND_DELAY: u16 = 4; /* wait for upper layer hint */
pub const ND_PROBE: u16 = 5; /* send probes */
pub const ND_UNREACHABLE: u16 = 6; /* delete this route */
pub const ND_INITIAL: u16 = 7; /* ipv4: arp resolution has not been sent yet */

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ndp_type {
    NDP_TYPE_OTHER = 1,
    NDP_TYPE_DYNAMIC,
    NDP_TYPE_STATIC,
    NDP_TYPE_LOCAL,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ndpr_entry {
    pub ndpre_ifname: [c_uchar; LIFNAMSIZ],
    pub ndpre_l2_addr: [u8; ND_MAX_HDW_LEN],
    pub ndpre_l2_addr_length: u8,
    pub ndpre_l3_addr: in6_addr,
    pub ndpre_state: u16,
    pub ndpre_type: ndp_type,
}

impl Default for ndpr_entry {
    fn default() -> ndpr_entry {
        ndpr_entry {
            ndpre_ifname: [0; LIFNAMSIZ],
            ndpre_l2_addr: [0; ND_MAX_HDW_LEN],
            ndpre_l2_addr_length: 0,
            ndpre_l3_addr: libc::in6_addr { s6_addr: [0; 16] },
            ndpre_state: ND_UNCHANGED,
            ndpre_type: ndp_type::NDP_TYPE_OTHER,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ndpreq {
    pub ndpr_count: u32,
    pub ndpr_buf: caddr_t,
}

pub const KSTAT_STRLEN: u32 = 31;
pub const KSTAT_TYPE_RAW: u32 = 0;
pub const KSTAT_TYPE_NAMED: u32 = 1;
pub const KSTAT_TYPE_INTR: u32 = 2;
pub const KSTAT_TYPE_IO: u32 = 3;
pub const KSTAT_TYPE_TIMER: u32 = 4;
pub const KSTAT_NUM_TYPES: u32 = 5;
pub const KSTAT_FLAG_VIRTUAL: u32 = 1;
pub const KSTAT_FLAG_VAR_SIZE: u32 = 2;
pub const KSTAT_FLAG_WRITABLE: u32 = 4;
pub const KSTAT_FLAG_PERSISTENT: u32 = 8;
pub const KSTAT_FLAG_DORMANT: u32 = 16;
pub const KSTAT_FLAG_INVALID: u32 = 32;
pub const KSTAT_FLAG_LONGSTRINGS: u32 = 64;
pub const KSTAT_READ: u32 = 0;
pub const KSTAT_WRITE: u32 = 1;
pub const KSTAT_DATA_CHAR: u32 = 0;
pub const KSTAT_DATA_INT32: u32 = 1;
pub const KSTAT_DATA_UINT32: u32 = 2;
pub const KSTAT_DATA_INT64: u32 = 3;
pub const KSTAT_DATA_UINT64: u32 = 4;
pub const KSTAT_DATA_LONG: u32 = 3;
pub const KSTAT_DATA_ULONG: u32 = 4;
pub const KSTAT_DATA_STRING: u32 = 9;
pub const KSTAT_DATA_LONGLONG: u32 = 3;
pub const KSTAT_DATA_ULONGLONG: u32 = 4;
pub const KSTAT_DATA_FLOAT: u32 = 5;
pub const KSTAT_DATA_DOUBLE: u32 = 6;
pub const KSTAT_INTR_HARD: u32 = 0;
pub const KSTAT_INTR_SOFT: u32 = 1;
pub const KSTAT_INTR_WATCHDOG: u32 = 2;
pub const KSTAT_INTR_SPURIOUS: u32 = 3;
pub const KSTAT_INTR_MULTSVC: u32 = 4;
pub const KSTAT_NUM_INTRS: u32 = 5;

pub const EPERM: u32 = 1;
pub const ENOENT: u32 = 2;
pub const ESRCH: u32 = 3;
pub const EINTR: u32 = 4;
pub const EIO: u32 = 5;
pub const ENXIO: u32 = 6;
pub const E2BIG: u32 = 7;
pub const ENOEXEC: u32 = 8;
pub const EBADF: u32 = 9;
pub const ECHILD: u32 = 10;
pub const EAGAIN: u32 = 11;
pub const ENOMEM: u32 = 12;
pub const EACCES: u32 = 13;
pub const EFAULT: u32 = 14;
pub const ENOTBLK: u32 = 15;
pub const EBUSY: u32 = 16;
pub const EEXIST: u32 = 17;
pub const EXDEV: u32 = 18;
pub const ENODEV: u32 = 19;
pub const ENOTDIR: u32 = 20;
pub const EISDIR: u32 = 21;
pub const EINVAL: u32 = 22;
pub const ENFILE: u32 = 23;
pub const EMFILE: u32 = 24;
pub const ENOTTY: u32 = 25;
pub const ETXTBSY: u32 = 26;
pub const EFBIG: u32 = 27;
pub const ENOSPC: u32 = 28;
pub const ESPIPE: u32 = 29;
pub const EROFS: u32 = 30;
pub const EMLINK: u32 = 31;
pub const EPIPE: u32 = 32;
pub const EDOM: u32 = 33;
pub const ERANGE: u32 = 34;
pub const ENOMSG: u32 = 35;
pub const EIDRM: u32 = 36;
pub const ECHRNG: u32 = 37;
pub const EL2NSYNC: u32 = 38;
pub const EL3HLT: u32 = 39;
pub const EL3RST: u32 = 40;
pub const ELNRNG: u32 = 41;
pub const EUNATCH: u32 = 42;
pub const ENOCSI: u32 = 43;
pub const EL2HLT: u32 = 44;
pub const EDEADLK: u32 = 45;
pub const ENOLCK: u32 = 46;
pub const ECANCELED: u32 = 47;
pub const ENOTSUP: u32 = 48;
pub const EDQUOT: u32 = 49;
pub const EBADE: u32 = 50;
pub const EBADR: u32 = 51;
pub const EXFULL: u32 = 52;
pub const ENOANO: u32 = 53;
pub const EBADRQC: u32 = 54;
pub const EBADSLT: u32 = 55;
pub const EDEADLOCK: u32 = 56;
pub const EBFONT: u32 = 57;
pub const EOWNERDEAD: u32 = 58;
pub const ENOTRECOVERABLE: u32 = 59;
pub const ENOSTR: u32 = 60;
pub const ENODATA: u32 = 61;
pub const ETIME: u32 = 62;
pub const ENOSR: u32 = 63;
pub const ENONET: u32 = 64;
pub const ENOPKG: u32 = 65;
pub const EREMOTE: u32 = 66;
pub const ENOLINK: u32 = 67;
pub const EADV: u32 = 68;
pub const ESRMNT: u32 = 69;
pub const ECOMM: u32 = 70;
pub const EPROTO: u32 = 71;
pub const ELOCKUNMAPPED: u32 = 72;
pub const ENOTACTIVE: u32 = 73;
pub const EMULTIHOP: u32 = 74;
pub const EBADMSG: u32 = 77;
pub const ENAMETOOLONG: u32 = 78;
pub const EOVERFLOW: u32 = 79;
pub const ENOTUNIQ: u32 = 80;
pub const EBADFD: u32 = 81;
pub const EREMCHG: u32 = 82;
pub const ELIBACC: u32 = 83;
pub const ELIBBAD: u32 = 84;
pub const ELIBSCN: u32 = 85;
pub const ELIBMAX: u32 = 86;
pub const ELIBEXEC: u32 = 87;
pub const EILSEQ: u32 = 88;
pub const ENOSYS: u32 = 89;
pub const ELOOP: u32 = 90;
pub const ERESTART: u32 = 91;
pub const ESTRPIPE: u32 = 92;
pub const ENOTEMPTY: u32 = 93;
pub const EUSERS: u32 = 94;
pub const ENOTSOCK: u32 = 95;
pub const EDESTADDRREQ: u32 = 96;
pub const EMSGSIZE: u32 = 97;
pub const EPROTOTYPE: u32 = 98;
pub const ENOPROTOOPT: u32 = 99;
pub const EPROTONOSUPPORT: u32 = 120;
pub const ESOCKTNOSUPPORT: u32 = 121;
pub const EOPNOTSUPP: u32 = 122;
pub const EPFNOSUPPORT: u32 = 123;
pub const EAFNOSUPPORT: u32 = 124;
pub const EADDRINUSE: u32 = 125;
pub const EADDRNOTAVAIL: u32 = 126;
pub const ENETDOWN: u32 = 127;
pub const ENETUNREACH: u32 = 128;
pub const ENETRESET: u32 = 129;
pub const ECONNABORTED: u32 = 130;
pub const ECONNRESET: u32 = 131;
pub const ENOBUFS: u32 = 132;
pub const EISCONN: u32 = 133;
pub const ENOTCONN: u32 = 134;
pub const ESHUTDOWN: u32 = 143;
pub const ETOOMANYREFS: u32 = 144;
pub const ETIMEDOUT: u32 = 145;
pub const ECONNREFUSED: u32 = 146;
pub const EHOSTDOWN: u32 = 147;
pub const EHOSTUNREACH: u32 = 148;
pub const EWOULDBLOCK: u32 = 11;
pub const EALREADY: u32 = 149;
pub const EINPROGRESS: u32 = 150;
pub const ESTALE: u32 = 151;

pub const RTM_VERSION: u32 = 3;
pub const RTM_ADD: u32 = 1;
pub const RTM_DELETE: u32 = 2;
pub const RTM_CHANGE: u32 = 3;
pub const RTM_GET: u32 = 4;
pub const RTM_LOSING: u32 = 5;
pub const RTM_REDIRECT: u32 = 6;
pub const RTM_MISS: u32 = 7;
pub const RTM_LOCK: u32 = 8;
pub const RTM_OLDADD: u32 = 9;
pub const RTM_OLDDEL: u32 = 10;
pub const RTM_RESOLVE: u32 = 11;
pub const RTM_NEWADDR: u32 = 12;
pub const RTM_DELADDR: u32 = 13;
pub const RTM_IFINFO: u32 = 14;
pub const RTM_CHGADDR: u32 = 15;
pub const RTM_FREEADDR: u32 = 16;
pub const RTM_GETALL: u32 = 17;

pub const RTA_DST: u32 = 0x1;
pub const RTA_GATEWAY: u32 = 0x2;
pub const RTA_NETMASK: u32 = 0x4;
pub const RTA_GENMASK: u32 = 0x8;
pub const RTA_IFP: u32 = 0x10;
pub const RTA_IFA: u32 = 0x20;
pub const RTA_AUTHOR: u32 = 0x40;
pub const RTA_BRD: u32 = 0x80;
pub const RTA_SRC: u32 = 0x100;

pub const RTF_UP: u32 = 0x1; /* route usable */
pub const RTF_GATEWAY: u32 = 0x2; /* destination is a gateway */
pub const RTF_HOST: u32 = 0x4; /* host entry (net otherwise) */
pub const RTF_REJECT: u32 = 0x8; /* host or net unreachable */
pub const RTF_DYNAMIC: u32 = 0x10; /* created dynamically (by redirect) */
pub const RTF_MODIFIED: u32 = 0x20; /* modified dynamically (by redirect) */
pub const RTF_DONE: u32 = 0x40; /* message confirmed */
pub const RTF_MASK: u32 = 0x80; /* subnet mask present */
pub const RTF_CLONING: u32 = 0x100; /* generate new routes on use */
pub const RTF_XRESOLVE: u32 = 0x200; /* external daemon resolves name */
pub const RTF_LLINFO: u32 = 0x400; /* generated by ARP or ESIS */
pub const RTF_STATIC: u32 = 0x800; /* manually added */
pub const RTF_BLACKHOLE: u32 = 0x1000; /* just discard pkts (during updates) */
pub const RTF_PRIVATE: u32 = 0x2000; /* do not advertise this route */
pub const RTF_PROTO2: u32 = 0x4000; /* protocol specific routing flag */
pub const RTF_PROTO1: u32 = 0x8000; /* protocol specific routing flag */
pub const RTF_MULTIRT: u32 = 0x10000; /* multiroute */
pub const RTF_SETSRC: u32 = 0x20000; /* set default outgoing src address */
pub const RTF_INDIRECT: u32 = 0x40000; /* gateway not directly reachable */
pub const RTF_KERNEL: u32 = 0x80000; /* created by kernel; can't delete */
pub const RTF_ZONE: u32 = 0x100000; /* (NGZ only) route from global zone */

extern "C" {
    pub fn getpid() -> pid_t;
}

/* error codes */
#[repr(C)]
pub enum IpadmStatusT {
    Success,            /* No error occurred */
    Failure,            /* Generic failure */
    Eauth,              /* Insufficient user authorizations */
    Eperm,              /* Permission denied */
    NoBufs,             /* No Buffer space available */
    NoMemory,           /* Insufficient memory */
    BadAddr,            /* Invalid address */
    BadProtocol,        /* Wrong protocol family for operation */
    DadFound,           /* Duplicate address detected */
    Exists,             /* Already exists */
    IfExists,           /* Interface already exists */
    AddrobjExists,      /* Address object already exists */
    AddrconfExists,     /* Addrconf already in progress */
    Enxio,              /* Interface does not exist */
    GrpNotEmpty,        /* IPMP Group non-empty on unplumb */
    InvalidArg,         /* Invalid argument */
    InvalidName,        /* Invalid name */
    DlpiFailure,        /* Could not open DLPI link */
    DladmFailure,       /* DLADM error encountered */
    PropUnknown,        /* Unknown property */
    Erange,             /* Value is outside the allowed range */
    Esrch,              /* Value does not exist */
    Eoverflow,          /* Number of values exceed the allowed limit*/
    NotFound,           /* Object not found */
    IfInuse,            /* Interface already in use */
    AddrInuse,          /* Address alrelady in use */
    BadHostname,        /* hostname maps to multiple IP addresses */
    AddrNotavail,       /* Can't assign requested address */
    AllAddrsNotEnabled, /* All addresses could not be enabled */
    NdpdNotRunning,     /* in.ndpd not running */
    DhcpStartError,     /* Cannot start dhcpagent */
    DhcpIpcError,       /* Cannot communicate with dhcpagent */
    DhcpIpcTimeout,     /* Communication with dhcpagent timed out */
    TemporaryObj,       /* Permanent operation on temporary object */
    IpcError,           /* Cannot communicate with ipmgmtd */
    OpDisableObj,       /* Operation on disable object */
    NotSup,             /* Operation not supported */
    Ebade,              /* Invalid data exchange with ipmgmtd */
    GzPerm,             /* Operation not permitted on from-gz intf */
}
