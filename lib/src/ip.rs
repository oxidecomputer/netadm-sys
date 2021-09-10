// Copyright 2021 Oxide Computer Company

use crate::nvlist::{NvDataType, NvHeader, NvPair, Value, NVP};
use rusty_doors::{door_call, door_callp};
use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CStr;
use std::fs::File;
use std::mem::{align_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use tracing::{debug, trace, warn};

#[derive(Debug)]
#[repr(i32)]
pub enum IpmgmtCmd {
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

#[derive(Debug)]
#[repr(C)]
pub struct IpmgmtGetRval {
    pub err: i32,
    pub nval_size: u32,
    /* native-encoded nvlist follows*/
}

impl Default for IpmgmtGetRval {
    fn default() -> Self {
        IpmgmtGetRval {
            err: 0,
            nval_size: 0,
        }
    }
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

pub fn get_persistent_ipinfo() -> Result<HashMap<String, HashMap<String, IpInfo>>, String> {
    unsafe {
        //// call the ipadmd door to get address information

        let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")
            .map_err(|e| format!("door open: {}", e))?;

        // This memory may get realloc'd by the door call, so we cannot use a Box :/
        let mut response: *mut IpmgmtGetRval = rusty_doors::sys::malloc(std::mem::size_of::<
            IpmgmtGetRval,
        >() as u64) as *mut IpmgmtGetRval;

        let request = IpmgmtGetAddr {
            ..Default::default()
        };
        let resp: *mut IpmgmtGetRval = door_callp(f.as_raw_fd(), request, &mut response);
        trace!("got {} bytes of nval", (*resp).nval_size);

        //// extract nvlist  header

        let nvh = (response.offset(1) as *const IpmgmtGetRval) as *mut NvHeader;
        trace!("found nvl header {:?}", *nvh);

        //// set up iteration pointer and consumption counter

        // NOTE! somehwere in the packing process an 8 byte padd is added
        // between the header and the first nvpair
        let sk = ((nvh.offset(1) as *const NvHeader) as *const u8).offset(0) as *const u8;
        let skipped = std::slice::from_raw_parts(sk, 8);
        warn!("skipping {:x?}", skipped);
        let p = ((nvh.offset(1) as *const NvHeader) as *const u8).offset(8) as *const u8;

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

        rusty_doors::sys::free(resp as *mut std::os::raw::c_void);

        Ok(handle_nvps(&nvps))
    }
}

fn handle_nvps(nvps: &Vec<NVP<'static>>) -> HashMap<String, HashMap<String, IpInfo>> {
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
            Some(hm) => {
                match hm.get_mut(&ip_info.addr_obj.clone()) {
                    Some(ipi) => {
                        match &mut ipi.properties {
                            IpProperties::Dhcp(dcp) => {
                                match ip_info.properties {
                                    IpProperties::Dhcp(dcpi) => {
                                        match dcpi.parameters {
                                            Some(ps) => dcp.parameters = Some(ps),
                                            None => {}
                                        }
                                        match dcpi.reqhost {
                                            Some(rh) => dcp.reqhost = Some(rh),
                                            None => {}
                                        }
                                    }
                                    // multiset only supported for dhcp
                                    _ => {}
                                }
                            }
                            // multiset only supported for dhcp
                            _ => {}
                        }
                    }
                    None => {
                        hm.insert(ip_info.addr_obj.clone(), ip_info);
                    }
                }
            }
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
            match part.value {
                Value::Str(s) => if_name = Some(s.to_string()),
                _ => {}
            }
        }

        if part.name == "_aobjname" {
            match part.value {
                Value::Str(s) => addr_obj = Some(s.to_string()),
                _ => {}
            }
        }

        if part.name == "_dhcp" {
            match &part.value {
                Value::NvList(vs) => {
                    let mut dcp = DhcpClientParameters {
                        wait: -1,
                        primary: false,
                    };
                    for v in vs.iter() {
                        if v.name == "wait" {
                            match v.value {
                                Value::Int32(i) => dcp.wait = i,
                                _ => {}
                            }
                        }
                        if v.name == "primary" {
                            match v.value {
                                Value::Boolean(b) => dcp.primary = b,
                                _ => {}
                            }
                        }
                    }
                    match &mut ip_properties {
                        Some(props) => match props {
                            IpProperties::Dhcp(props) => props.parameters = Some(dcp),
                            _ => {
                                warn!("dhcp client params found in non-dhcp record");
                            }
                        },
                        None => {
                            ip_properties = Some(IpProperties::Dhcp(DhcpProperties {
                                parameters: Some(dcp),
                                reqhost: None,
                            }));
                        }
                    }
                }
                _ => {}
            };
        }

        if part.name == "reqhost" {
            match &part.value {
                Value::Str(s) => match &mut ip_properties {
                    Some(props) => match props {
                        IpProperties::Dhcp(props) => {
                            props.reqhost = Some(s.to_string());
                        }
                        _ => {
                            warn!("dhcp reqhost found in non-dhcp record")
                        }
                    },
                    None => {
                        ip_properties = Some(IpProperties::Dhcp(DhcpProperties {
                            parameters: None,
                            reqhost: Some(s.to_string()),
                        }));
                    }
                },
                _ => {}
            }
        }

        if part.name == "_intfid" {
            match &part.value {
                Value::NvList(vs) => {
                    let mut intfid = Intfid {
                        prefix_len: 0,
                        addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                        stateless: false,
                        stateful: false,
                    };
                    for v in vs.iter() {
                        if v.name == "prefixlen" {
                            match v.value {
                                Value::Uint32(u) => intfid.prefix_len = u,
                                _ => {}
                            }
                        }
                        if v.name == "_addr" {
                            match v.value {
                                Value::Uint8Array(u) => {
                                    intfid.addr = match u.try_into()
                                        as Result<[u8; 16], <&[u8] as TryInto<[u8; 16]>>::Error>
                                    {
                                        Ok(addr) => Ipv6Addr::from(addr),
                                        Err(_) => continue,
                                    }
                                }
                                _ => {}
                            }
                        }
                        if v.name == "_stateless" {
                            match v.value {
                                Value::Str(b) => match b {
                                    "yes" => intfid.stateless = true,
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                        if v.name == "_stateful" {
                            match v.value {
                                Value::Str(b) => match b {
                                    "yes" => intfid.stateful = true,
                                    _ => {}
                                },
                                _ => {}
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
                _ => {}
            }
        }

        if part.name == "_ipv4addr" {
            match &part.value {
                Value::NvList(vs) => {
                    for v in vs.iter() {
                        match &v.value {
                            Value::Str(s) => match Ipv4Addr::from_str(s) {
                                Ok(addr) => {
                                    ip_properties =
                                        Some(IpProperties::V4Static(V4Static { addr: addr }));
                                }
                                _ => {
                                    warn!("bad ipv4 address: {}", s)
                                }
                            },
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        if part.name == "_ipv6addr" {
            match &part.value {
                Value::NvList(vs) => {
                    for v in vs.iter() {
                        match &v.value {
                            Value::Str(s) => match Ipv6Addr::from_str(s) {
                                Ok(addr) => {
                                    ip_properties =
                                        Some(IpProperties::V6Static(V6Static { addr: addr }));
                                }
                                _ => {
                                    warn!("bad ipv6 address: {}", s)
                                }
                            },
                            _ => {}
                        }
                    }
                }
                _ => {}
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
                consumed = consumed + 4;
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
            consumed = consumed + sz as i32;
            trace!("consumed {}", consumed);
            if consumed >= size {
                break;
            }

            match nv.value {
                Value::NvList(_) => {
                    let (embedded_nvps, embedded_consumed) = extract_nvps(p, size - consumed);
                    nvps.push(NVP {
                        name: nv.name,
                        value: Value::NvList(embedded_nvps),
                    });
                    consumed = consumed + embedded_consumed;
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
            let slice = std::slice::from_raw_parts(p, (*nvp).name_size as usize);
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
                    ((*nvp).size - (*nvp).name_size as i32 - size_of::<NvPair>() as i32 - 1)
                        as usize,
                );
                let cstr = std::ffi::CStr::from_bytes_with_nul_unchecked(slice);
                let decoded = match cstr.to_str() {
                    Ok(s) => s,
                    Err(_) => "<udecodable value>",
                };
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
                let ua = std::slice::from_raw_parts(v, (*nvp).value_count as usize);
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

pub fn ifname_to_addrobj(mut if_name: &str, addr_family: u16) -> Result<(String, String), String> {
    let parts: Vec<&str> = if_name.split(':').collect();
    let num = match parts.len() {
        2 => match i32::from_str_radix(parts[1], 10) {
            Ok(n) => {
                if_name = parts[0];
                n
            }
            Err(_) => 0,
        },
        _ => 0,
    };

    let mut ia_ifname = [0; 32usize];
    for (i, _) in if_name.chars().enumerate() {
        ia_ifname[i] = if_name.as_bytes()[i] as std::os::raw::c_char;
    }

    let request = crate::sys::ipmgmt_aobjop_arg_t {
        ia_cmd: crate::sys::ipmgmt_door_cmd_type_t_IPMGMT_CMD_LIF2ADDROBJ,
        ia_flags: 0,
        ia_aobjname: [0; 64usize],
        ia_ifname: ia_ifname,
        ia_lnum: num,
        ia_family: addr_family,
        ia_atype: crate::sys::ipadm_addr_type_t_IPADM_ADDR_NONE,
    };

    let f = File::open("/etc/svc/volatile/ipadm/ipmgmt_door")
        .map_err(|e| format!("door open: {}", e))?;

    let resp: crate::sys::ipmgmt_aobjop_rval_t = door_call(f.as_raw_fd(), request);

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
