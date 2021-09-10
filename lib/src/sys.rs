// Copyright 2021 Oxide Computer Company

// import generated bindings
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]
#![allow(deref_nullptr)]
#![allow(unaligned_references)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

//TODO work to get ipmgmt types exported by illumos, but not with ipadm types in
//the mix, this will require some work on the ipmgmt data structures to
//eradicate dladm types

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
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_RESETADDR: ipmgmt_door_cmd_type_t = 8;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_RESETPROP: ipmgmt_door_cmd_type_t = 9;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_INITIF: ipmgmt_door_cmd_type_t = 10;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_ADDROBJ_LOOKUPADD: ipmgmt_door_cmd_type_t = 11;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_ADDROBJ_SETLIFNUM: ipmgmt_door_cmd_type_t = 12;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_ADDROBJ_ADD: ipmgmt_door_cmd_type_t = 13;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_LIF2ADDROBJ: ipmgmt_door_cmd_type_t = 14;
pub const ipmgmt_door_cmd_type_t_IPMGMT_CMD_AOBJNAME2ADDROBJ: ipmgmt_door_cmd_type_t = 15;
pub type ipmgmt_door_cmd_type_t = ::std::os::raw::c_uint;

#[repr(C)]
#[derive(Copy, Clone)]
pub union ipmgmt_addr_type_cache_u {
    pub ipmgmt_ipv6_cache_s: ipmgmt_addr_type_cache_u__bindgen_ty_1,
    pub ipmgmt_dhcp_cache_s: ipmgmt_addr_type_cache_u__bindgen_ty_2,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ipmgmt_addr_type_cache_u__bindgen_ty_1 {
    pub ipmgmt_linklocal: boolean_t,
    pub ipmgmt_ifid: sockaddr_in6,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ipmgmt_addr_type_cache_u__bindgen_ty_2 {
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
                ipmgmt_ipv6_cache_s: ipmgmt_addr_type_cache_u__bindgen_ty_1 {
                    ipmgmt_linklocal: 0,
                    ipmgmt_ifid: sockaddr_in6 {
                        sin6_family: 0,
                        sin6_port: 0,
                        sin6_flowinfo: 0,
                        sin6_addr: in6_addr {
                            _S6_un: in6_addr__bindgen_ty_1 { __S6_align: 0 },
                        },
                        sin6_scope_id: 0,
                        __sin6_src_id: 0,
                    },
                },
            },
        }
    }
}
