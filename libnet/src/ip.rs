// Copyright 2021 Oxide Computer Company

use crate::nvlist::{NvDataType, NvHeader, NvPair, Value, NVP};
use libc::{free, malloc, sockaddr_in6};
use rusty_doors::{door_call, door_callp};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::mem::{align_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::str::FromStr;
use tracing::{debug, trace, warn};

#[derive(Debug)]
#[repr(i32)]
pub enum IpmgmtCmd {
    Unset = 0,
    SetProp = 1,
    SetIf = 2,
    SetAddr = 3,
    GetProp = 4,
    GetIf = 5,
    GetAddr = 6,
    ResetIf = 7,
    ResetAddr = 8,
    ResetProp = 9,
    InitIf = 10,
    AddrobjLookupAdd = 11,
    AddrobjSetLifnum = 12,
    AddrobjAdd = 13,
    Lif2Addrobj = 14,
    AobjName2Addrobj = 15,
}

#[derive(Debug)]
#[repr(C)]
pub struct IpmgmtGetAddr {
    pub cmd: IpmgmtCmd,
    pub flags: u32,
    pub ifname: [u8; 32],
    pub family: u16,
    pub objname: [u8; 64],
}

#[derive(Debug)]
#[repr(C)]
pub struct IpmgmtSetAddr {
    pub cmd: IpmgmtCmd,
    pub flags: u32,

    //NOTE: this is a size_t in libipadm.h which is bad news for doors
    pub nvlsize: u32,
}

impl Default for IpmgmtGetAddr {
    fn default() -> Self {
        IpmgmtGetAddr {
            cmd: IpmgmtCmd::GetAddr,
            flags: 0,
            ifname: [0; 32],
            family: 0,
            objname: [0; 64],
        }
    }
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct IpmgmtRval {
    pub err: i32,
}

#[derive(Debug, Default)]
#[repr(C)]
pub struct IpmgmtGetRval {
    pub err: i32,
    pub nval_size: u32,
    /* native-encoded nvlist follows*/
}

pub const LIFNAMSIZ: u32 = 32;
pub const IPADM_AOBJ_USTRSIZ: u32 = 32;
pub const IPADM_AOBJSIZ: u32 = LIFNAMSIZ + IPADM_AOBJ_USTRSIZ;

#[derive(Debug, Copy, Clone)]
#[repr(i32)]
pub enum AddrType {
    AddrNone,
    Static,
    Ipv6Addrconf,
    Dhcp,
}

impl Default for AddrType {
    fn default() -> Self {
        AddrType::AddrNone
    }
}

#[repr(C)]
pub struct IpmgmtAobjopArg {
    pub cmd: IpmgmtCmd,
    pub flags: u32,
    pub objname: [c_char; IPADM_AOBJSIZ as usize],
    pub ifname: [c_char; LIFNAMSIZ as usize],
    pub lnum: i32,
    pub family: u16,
    pub atype: AddrType,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IpmgmtAobjopRval {
    pub err: i32,
    pub objname: [c_char; IPADM_AOBJSIZ as usize],
    pub ifname: [c_char; LIFNAMSIZ as usize],
    pub lnum: i32,
    pub family: u16,
    pub flags: u32,
    pub atype: AddrType,
    pub atype_cache: IpmgmtAddrTypeCache,
}

impl Default for IpmgmtAobjopRval {
    fn default() -> Self {
        IpmgmtAobjopRval {
            err: 0,
            objname: [0; IPADM_AOBJSIZ as usize],
            ifname: [0; LIFNAMSIZ as usize],
            lnum: 0,
            family: 0,
            flags: 0,
            atype: AddrType::default(),
            atype_cache: IpmgmtAddrTypeCache::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IpmgmtAddrTypeCache {
    pub ipv6_cache: IpmgmtIpv6Cache,
    pub dhcp_cache: IpmgmtDhcpCache,
}

impl Default for IpmgmtAddrTypeCache {
    fn default() -> Self {
        IpmgmtAddrTypeCache {
            ipv6_cache: IpmgmtIpv6Cache::default(),
        }
    }
}

// for C interop compat
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum BooleanT {
    False,
    True,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IpmgmtIpv6Cache {
    pub linklocal: BooleanT,
    pub ifid: sockaddr_in6,
}

impl Default for IpmgmtIpv6Cache {
    fn default() -> Self {
        IpmgmtIpv6Cache {
            linklocal: BooleanT::False,
            ifid: sockaddr_in6 {
                sin6_family: 0,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
                ..unsafe { std::mem::zeroed() }
            },
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IpmgmtDhcpCache {
    pub reqhost: [c_char; 256usize],
}

impl Default for IpmgmtDhcpCache {
    fn default() -> Self {
        IpmgmtDhcpCache { reqhost: [0; 256] }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct IpmgmtAddrArg {
    pub cmd: IpmgmtCmd,
    pub flags: u32,
    pub objname: [c_char; IPADM_AOBJSIZ as usize],
    pub lnum: u32,
}

#[derive(Debug)]
pub struct IpInfo {
    pub if_name: String,
    pub addr_obj: String,
    pub properties: IpProperties,
}

#[derive(Debug)]
pub enum IpProperties {
    Dhcp(DhcpProperties),
    Intfid(Intfid),
    V4Static(V4Static),
    V6Static(V6Static),
}

#[derive(Debug)]
pub struct DhcpProperties {
    pub parameters: Option<DhcpClientParameters>,
    pub reqhost: Option<String>,
}

#[derive(Debug)]
pub struct DhcpClientParameters {
    pub wait: i32,
    pub primary: bool,
}

#[derive(Debug)]
pub struct V4Static {
    pub addr: Ipv4Addr,
}

#[derive(Debug)]
pub struct V6Static {
    pub addr: Ipv6Addr,
}

#[derive(Debug)]
pub struct Intfid {
    pub prefix_len: u32,
    pub addr: Ipv6Addr,
    pub stateless: bool,
    pub stateful: bool,
}

pub fn get_persistent_ipinfo(
) -> Result<HashMap<String, HashMap<String, IpInfo>>, String> {
    unsafe {
        //// call the ipadmd door to get address information

        let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")
            .map_err(|e| format!("door open: {}", e))?;

        // This memory may get realloc'd by the door call, so we cannot use a
        // Box :/
        let mut response: *mut IpmgmtGetRval =
            malloc(std::mem::size_of::<IpmgmtGetRval>()) as *mut IpmgmtGetRval;

        let request = IpmgmtGetAddr {
            ..Default::default()
        };
        let resp: *mut IpmgmtGetRval = door_callp(
            f.as_raw_fd(),
            request,
            ptr::NonNull::new(&mut response).unwrap(), // null not possible
        );
        trace!("got {} bytes of nval", (*resp).nval_size);

        //// extract nvlist  header

        let nvh = (response.offset(1) as *const IpmgmtGetRval) as *mut NvHeader;
        trace!("found nvl header {:?}", *nvh);

        //// set up iteration pointer and consumption counter

        // NOTE! somehwere in the packing process an 8 byte padd is added
        // between the header and the first nvpair
        let sk = ((nvh.offset(1) as *const NvHeader) as *const u8).offset(0)
            as *const u8;
        let skipped = std::slice::from_raw_parts(sk, 8);
        warn!("skipping {:x?}", skipped);
        let p = ((nvh.offset(1) as *const NvHeader) as *const u8).offset(8)
            as *const u8;

        // NOTE! i've observed that `nval_size` can be larger than the
        // actual size of the list. We are relying on zero-sized nvpair
        // detection to exit processing lists. However, if there is ever a list
        // that is not terminated with a zero-sized nvpair AND the `nval_size` is
        // larger than the list actually is, we can get undefined behavior. The
        // `end` property is plumbed down to the `extract_nvps` function
        // primarily as a safeguard to keep the iteration from running unbounded
        // in the case that the nvlist is not terminated with a zero-sized nvpair.
        let end = (*resp).nval_size as i32;

        //// extract the name value pairs

        let (nvps, _) = extract_nvps(p, end);
        trace!("NVPs: {:#?}", nvps);

        free(resp as *mut std::os::raw::c_void);

        Ok(handle_nvps(&nvps))
    }
}

fn handle_nvps(
    nvps: &[NVP<'static>],
) -> HashMap<String, HashMap<String, IpInfo>> {
    let mut result = HashMap::new();

    for nvp in nvps.iter() {
        let ip_info = match handle_nvp(nvp) {
            Some(ip_info) => ip_info,
            None => continue,
        };

        match result.get_mut(&ip_info.if_name) {
            None => {
                let mut hm = HashMap::new();
                let k = ip_info.if_name.clone();
                hm.insert(ip_info.addr_obj.clone(), ip_info);
                result.insert(k, hm);
            }
            Some(hm) => match hm.get_mut(&ip_info.addr_obj.clone()) {
                Some(ipi) => {
                    if let IpProperties::Dhcp(dcp) = &mut ipi.properties {
                        if let IpProperties::Dhcp(dcpi) = ip_info.properties {
                            if let Some(ps) = dcpi.parameters {
                                dcp.parameters = Some(ps)
                            }
                            if let Some(rh) = dcpi.reqhost {
                                dcp.reqhost = Some(rh)
                            }
                        }
                    }
                }
                None => {
                    hm.insert(ip_info.addr_obj.clone(), ip_info);
                }
            },
        }
    }

    debug!("ipinfos: {:#?}", result);

    result
}

// TODO this cornucopia of sadness shows why nvlists should be handled by serde
// ....
fn handle_nvp(nvp: &NVP<'static>) -> Option<IpInfo> {
    let parts = match &nvp.value {
        Value::NvList(parts) => parts,
        _ => {
            // having a property all on it's own makes no sense, ipmgmtd entries
            // always come with at least an `_ifname` and some other property
            warn!(
                "Disaggregated ipmgmt property detected: {}. Skipping",
                nvp.name
            );
            return None;
        }
    };

    let mut if_name: Option<String> = None;
    let mut addr_obj: Option<String> = None;
    let mut ip_properties: Option<IpProperties> = None;

    for part in parts.iter() {
        if part.name == "_ifname" {
            if let Value::Str(s) = part.value {
                if_name = Some(s.to_string());
            }
        }

        if part.name == "_aobjname" {
            if let Value::Str(s) = part.value {
                addr_obj = Some(s.to_string());
            }
        }

        if part.name == "_dhcp" {
            if let Value::NvList(vs) = &part.value {
                let mut dcp = DhcpClientParameters {
                    wait: -1,
                    primary: false,
                };
                for v in vs.iter() {
                    if v.name == "wait" {
                        if let Value::Int32(i) = v.value {
                            dcp.wait = i;
                        }
                    }
                    if v.name == "primary" {
                        if let Value::Boolean(b) = v.value {
                            dcp.primary = b;
                        }
                    }
                }
                match &mut ip_properties {
                    Some(props) => match props {
                        IpProperties::Dhcp(props) => {
                            props.parameters = Some(dcp)
                        }
                        _ => {
                            warn!("dhcp client params in non-dhcp record");
                        }
                    },
                    None => {
                        ip_properties =
                            Some(IpProperties::Dhcp(DhcpProperties {
                                parameters: Some(dcp),
                                reqhost: None,
                            }));
                    }
                }
            };
        }

        if part.name == "reqhost" {
            if let Value::Str(s) = &part.value {
                match &mut ip_properties {
                    Some(props) => match props {
                        IpProperties::Dhcp(props) => {
                            props.reqhost = Some(s.to_string());
                        }
                        _ => {
                            warn!("dhcp reqhost found in non-dhcp record")
                        }
                    },
                    None => {
                        ip_properties =
                            Some(IpProperties::Dhcp(DhcpProperties {
                                parameters: None,
                                reqhost: Some(s.to_string()),
                            }));
                    }
                }
            }
        }

        if part.name == "_intfid" {
            if let Value::NvList(vs) = &part.value {
                let mut intfid = Intfid {
                    prefix_len: 0,
                    addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    stateless: false,
                    stateful: false,
                };
                for v in vs.iter() {
                    if v.name == "prefixlen" {
                        if let Value::Uint32(u) = v.value {
                            intfid.prefix_len = u;
                        }
                    }
                    if v.name == "_addr" {
                        if let Value::Uint8Array(u) = v.value {
                            intfid.addr = match u.try_into()
                                as Result<
                                    [u8; 16],
                                    <&[u8] as TryInto<[u8; 16]>>::Error,
                                > {
                                Ok(addr) => Ipv6Addr::from(addr),
                                Err(_) => continue,
                            }
                        }
                    }
                    if v.name == "_stateless" {
                        if let Value::Str(b) = v.value {
                            if b == "yes" {
                                intfid.stateless = true;
                            }
                        }
                    }
                    if v.name == "_stateful" {
                        if let Value::Str(b) = v.value {
                            if b == "yes" {
                                intfid.stateful = true
                            }
                        }
                    }
                }
                match &mut ip_properties {
                    Some(_) => {
                        warn!("duplicate v6 properties");
                    }
                    None => {
                        ip_properties = Some(IpProperties::Intfid(intfid));
                    }
                }
            }
        }

        if part.name == "_ipv4addr" {
            if let Value::NvList(vs) = &part.value {
                for v in vs.iter() {
                    if let Value::Str(s) = &v.value {
                        match Ipv4Addr::from_str(s) {
                            Ok(addr) => {
                                ip_properties =
                                    Some(IpProperties::V4Static(V4Static {
                                        addr,
                                    }));
                            }
                            _ => {
                                warn!("bad ipv4 address: {}", s)
                            }
                        }
                    }
                }
            }
        }

        if part.name == "_ipv6addr" {
            if let Value::NvList(vs) = &part.value {
                for v in vs.iter() {
                    if let Value::Str(s) = &v.value {
                        match Ipv6Addr::from_str(s) {
                            Ok(addr) => {
                                ip_properties =
                                    Some(IpProperties::V6Static(V6Static {
                                        addr,
                                    }));
                            }
                            _ => {
                                warn!("bad ipv6 address: {}", s)
                            }
                        }
                    }
                }
            }
        }
    }

    match (if_name, addr_obj, ip_properties) {
        (Some(n), Some(a), Some(p)) => Some(IpInfo {
            if_name: n,
            addr_obj: a,
            properties: p,
        }),
        _ => None,
    }
}

fn extract_nvps(mut p: *const u8, size: i32) -> (Vec<NVP<'static>>, i32) {
    let mut nvps = Vec::new();
    let mut consumed = 0;

    unsafe {
        //// Iterate over nvpairs in the nvlist

        loop {
            let sz = *(p as *const i32);
            if sz == 0 {
                trace!("found zero sized nvpair, return from extract");
                consumed += 4;
                //p = p.add(4);
                return (nvps, consumed);
            }
            let nvp = p as *const NvPair;
            let nv = match extract_nvp(nvp) {
                Ok(nv) => nv,
                Err(e) => {
                    warn!("nv extraction failed: {}", e);
                    continue;
                }
            };

            p = p.add(sz as usize);
            p = p.add(p.align_offset(align_of::<u32>()));
            consumed += sz as i32;
            trace!("consumed {}", consumed);
            if consumed >= size {
                break;
            }

            match nv.value {
                Value::NvList(_) => {
                    let (embedded_nvps, embedded_consumed) =
                        extract_nvps(p, size - consumed);

                    nvps.push(NVP {
                        name: nv.name,
                        value: Value::NvList(embedded_nvps),
                    });
                    consumed += embedded_consumed;
                    p = p.add(embedded_consumed as usize);
                }
                _ => {
                    nvps.push(nv);
                }
            }
        }
    }

    (nvps, consumed)
}

fn extract_nvp(nvp: *const NvPair) -> Result<NVP<'static>, String> {
    let mut result = NVP {
        name: "?",
        value: Value::Unknown,
    };

    unsafe {
        //// extract name

        trace!("nvp: {:?}", *nvp);
        let p = ((nvp.offset(1) as *const NvPair) as *const u8) as *mut u8;
        let name = {
            let slice =
                std::slice::from_raw_parts(p, (*nvp).name_size as usize);
            let cstr = std::ffi::CStr::from_bytes_with_nul_unchecked(slice);
            match cstr.to_str() {
                Ok(s) => s,
                Err(e) => return Err(format!("name to string: {}", e)),
            }
        };
        result.name = name;
        trace!("  name: {:?}", name);

        //// extract value

        let mut v = p.offset((*nvp).name_size as isize);
        v = v.add(v.align_offset(align_of::<u32>()));

        match (*nvp).typ {
            NvDataType::Str => {
                let slice = std::slice::from_raw_parts(
                    v,
                    ((*nvp).size
                        - (*nvp).name_size as i32
                        - size_of::<NvPair>() as i32
                        - 1) as usize,
                );
                let cstr = std::ffi::CStr::from_bytes_with_nul_unchecked(slice);
                let decoded = cstr.to_str().unwrap_or("<undecodable value>");
                //TODO no idea why some strings come back with leading and
                //trailing zeros
                let trimmed = decoded.trim_matches('\u{0}');
                result.value = Value::Str(trimmed);
                trace!("  value: {:?}", trimmed);
            }

            NvDataType::BooleanValue => {
                let b = *(v as *const bool);
                result.value = Value::Boolean(b);
                trace!("  value: {}", b);
            }

            NvDataType::Int32 => {
                let i = *(v as *const i32);
                result.value = Value::Int32(i);
                trace!("  value: {}", i);
            }

            NvDataType::Uint32 => {
                let u = *(v as *const u32);
                result.value = Value::Uint32(u);
                trace!("  value: {}", u);
            }

            NvDataType::Uint8Array => {
                let ua =
                    std::slice::from_raw_parts(v, (*nvp).value_count as usize);
                result.value = Value::Uint8Array(ua);
                trace!("  value: {:x?}", ua);
            }

            NvDataType::NvList => {
                result.value = Value::NvList(Vec::new());
            }

            _ => {}
        }
    }

    Ok(result)
}

//TODO this interface should return all information contained in addrobj_rtal_t
pub fn ifname_to_addrobj(
    mut if_name: &str,
    addr_family: u16,
) -> Result<(String, String), String> {
    let parts: Vec<&str> = if_name.split(':').collect();
    let num = match parts.len() {
        2 => match parts[1].parse::<i32>() {
            Ok(n) => {
                if_name = parts[0];
                n
            }
            Err(_) => 0,
        },
        _ => 0,
    };

    let mut ia_ifname = [0; 32usize];
    for (i, c) in if_name.chars().enumerate() {
        ia_ifname[i] = c as std::os::raw::c_char;
    }

    let request = crate::sys::ipmgmt_aobjop_arg_t {
        ia_ifname,
        ia_cmd: crate::sys::ipmgmt_door_cmd_type_t_IPMGMT_CMD_LIF2ADDROBJ,
        ia_flags: 0,
        ia_aobjname: [0; 64usize],
        ia_lnum: num,
        ia_family: addr_family,
        ia_atype: crate::sys::ipadm_addr_type_t_IPADM_ADDR_NONE,
    };

    let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")
        .map_err(|e| format!("door open: {}", e))?;

    let resp: crate::sys::ipmgmt_aobjop_rval_t =
        door_call(f.as_raw_fd(), request);

    let objname = unsafe {
        CStr::from_ptr(resp.ir_aobjname.as_ptr())
            .to_str()
            .map_err(|e| format!("abojname cstr to str: {}", e))?
            .to_string()
    };

    let source = match resp.ir_atype {
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_NONE => "none",
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_STATIC => "static",
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_IPV6_ADDRCONF => "addrconf",
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_DHCP => "dhcp",
        _ => "?",
    };

    Ok((objname, source.to_string()))
}

//TODO this interface should return all information contained in addrobj_rtal_t
//      in a sane way e.g. not a tuple
pub fn addrobjname_to_addrobj(
    aobj_name: &str,
) -> Result<(String, String, u16, String, i32), String> {
    let mut request = crate::sys::ipmgmt_aobjop_arg_t {
        ia_cmd: crate::sys::ipmgmt_door_cmd_type_t_IPMGMT_CMD_AOBJNAME2ADDROBJ,
        ia_flags: 0,
        ia_aobjname: [0; 64usize],
        ia_ifname: [0; 32usize],
        ia_lnum: 0,
        ia_family: 0,
        ia_atype: crate::sys::ipadm_addr_type_t_IPADM_ADDR_NONE,
    };
    for (i, c) in aobj_name.chars().enumerate() {
        request.ia_aobjname[i] = c as std::os::raw::c_char;
    }

    let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")
        .map_err(|e| format!("door open: {}", e))?;

    let resp: crate::sys::ipmgmt_aobjop_rval_t =
        door_call(f.as_raw_fd(), request);

    let ifname = unsafe {
        CStr::from_ptr(resp.ir_ifname.as_ptr())
            .to_str()
            .map_err(|e| format!("abojname cstr to str: {}", e))?
            .to_string()
    };

    let source = match resp.ir_atype {
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_NONE => "none",
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_STATIC => "static",
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_IPV6_ADDRCONF => "addrconf",
        crate::sys::ipadm_addr_type_t_IPADM_ADDR_DHCP => "dhcp",
        _ => "?",
    };

    Ok((
        aobj_name.to_string(),
        source.to_string(),
        resp.ir_family,
        ifname,
        resp.ir_lnum,
    ))
}
