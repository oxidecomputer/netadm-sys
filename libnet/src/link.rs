// Copyright 2021 Oxide Computer Company

use crate::sys;
use crate::{Error, LinkClass, LinkFlags, LinkInfo};
use libc::ENOENT;
use rusty_doors::door_call;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::str;
use tracing::{debug, warn};

const DATALINK_ANY_MEDIATYPE: u64 = 0x01 << 32;

#[derive(Debug)]
#[repr(u32)]
pub enum DlmgmtCmd {
    DLScreate = 1,
    DLSgetattr = 2,
    DLSdestroy = 3,
    GetName = 4,
    GetLinkId = 5,
    GetNext = 6,
    DLSupdate = 7,
    LinkPropInit = 8,
    SetZoneId = 9,
    CreateLinkId = 128,
    DestroyLinkId = 129,
    RemapLinkId = 130,
    CreateConf = 131,
    OpenConf = 132,
    WriteConf = 133,
    UpLinkId = 134,
    SetAttr = 135,
    UnsetAttr = 136,
    RemoveConf = 137,
    DestroyConf = 138,
    GetAttr = 139,
    GetConfSnapshot = 140,
    ZoneBoot = 141,
    ZoneHalt = 142,
}

#[derive(Debug)]
#[repr(C)]
pub struct DlmgmtGetNext {
    pub cmd: u32,
    pub linkid: u32,
    pub class: LinkClass,
    pub flags: LinkFlags,
    pub media: u64,
}

impl Default for DlmgmtGetNext {
    fn default() -> Self {
        DlmgmtGetNext {
            cmd: DlmgmtCmd::GetNext as u32,
            linkid: 0,
            class: LinkClass::All,
            flags: LinkFlags::ActivePersistent,
            media: DATALINK_ANY_MEDIATYPE,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct DlmgmtGetName {
    pub cmd: u32,
    pub linkid: u32,
}

impl Default for DlmgmtGetName {
    fn default() -> Self {
        DlmgmtGetName {
            cmd: DlmgmtCmd::GetName as u32,
            linkid: 0,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct DlmgmtNameRetval {
    pub err: u32,
    pub link: [u8; 32],
    pub class: LinkClass,
    pub media: u32,
    pub flags: LinkFlags,
}

impl Default for DlmgmtNameRetval {
    fn default() -> Self {
        DlmgmtNameRetval {
            err: 0,
            link: [0; 32],
            class: LinkClass::Phys,
            media: 0,
            flags: LinkFlags::ActivePersistent,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct DlmgmtLinkRetval {
    pub err: u32,
    pub linkid: u32,
    pub flags: LinkFlags,
    pub class: LinkClass,
    pub media: u32,
    pub padding: u32,
}

impl Default for DlmgmtLinkRetval {
    fn default() -> Self {
        DlmgmtLinkRetval {
            err: 0,
            linkid: 0,
            flags: LinkFlags::ActivePersistent,
            class: LinkClass::All,
            media: 0,
            padding: 0,
        }
    }
}

pub(crate) fn get_links() -> Result<Vec<LinkInfo>, Error> {
    let mut result = Vec::new();
    let mut linkid = 0;
    let f = dlmgmt_door_fd()?;

    loop {
        let request = DlmgmtGetNext {
            linkid,
            ..Default::default()
        };
        let response: DlmgmtLinkRetval = door_call(f.as_raw_fd(), request);

        if response.linkid == 0 || response.err == (ENOENT as u32) {
            break;
        }
        if response.err != 0 {
            warn!("Door error: {:#?}", response);
            break;
        }

        linkid = response.linkid;

        match get_link(response.linkid) {
            Ok(lnk) => result.push(lnk),
            Err(e) => warn!("{}", e),
        };
    }

    Ok(result)
}

pub(crate) fn get_link(id: u32) -> Result<LinkInfo, Error> {
    let f = dlmgmt_door_fd()?;

    let name_request = DlmgmtGetName {
        cmd: DlmgmtCmd::GetName as u32,
        linkid: id,
    };

    let response: DlmgmtNameRetval = door_call(f.as_raw_fd(), name_request);
    let name: &str = match response.err {
        0 => {
            let end = response
                .link
                .iter()
                .position(|&c| c == b'\0')
                .expect("bad link name");
            str::from_utf8(&response.link[0..end])?
        }
        _ => return Err(Error::NotFound(format!("link-id {} not found", id))),
    };

    let link_state = match crate::kstat::get_linkstate(name) {
        Ok(state) => match state {
            sys::link_state_t_LINK_STATE_UP => crate::LinkState::Up,
            sys::link_state_t_LINK_STATE_DOWN => crate::LinkState::Down,
            _ => crate::LinkState::Unknown,
        },
        Err(e) => {
            warn!("error fetching link state on linkid {}: {}", id, e);
            crate::LinkState::Unknown
        }
    };

    let mac = match crate::ioctl::get_macaddr(id) {
        Ok(mac) => mac,
        Err(e) => {
            warn!("error fetching mach address on linkid {}: {}", id, e);
            [0u8; 6]
        }
    };

    let over = match response.class {
        LinkClass::Simnet => match crate::ioctl::get_simnet_info(id) {
            Ok(info) => info.peer_link_id,
            Err(_) => {
                warn!("could not get vnic info for {} ({})", name, id);
                0
            }
        },
        LinkClass::Vnic => match crate::ioctl::get_vnic_info(id) {
            Ok(info) => info.link_id,
            Err(_) => {
                warn!("could not get vnic info for {} ({})", name, id);
                0
            }
        },
        _ => 0,
    };

    Ok(LinkInfo {
        id,
        mac,
        over,
        name: name.to_string(),
        flags: response.flags,
        class: response.class,
        state: link_state,
    })
}

#[repr(C)]
pub enum DlmgmtDoorAttrType {
    Str,
    Boolean,
    Uint64,
}

#[repr(C)]
struct DlmgmtDoorWriteConf {
    cmd: DlmgmtCmd,
    conf_id: u32,
}

#[repr(C)]
#[derive(Default)]
struct DlmgmtRetval {
    err: u32,
}

#[repr(C)]
struct DlmgmtDoorOpenConf {
    cmd: DlmgmtCmd,
    linkid: u32,
}

#[repr(C)]
#[derive(Default)]
struct DlmgmtOpenConfRetval {
    err: u32,
    conf_id: u32,
}

const MAXLINKATTRLEN: usize = 32;
const MAXLINKATTRVALLEN: usize = 1024;

#[repr(C)]
struct DlmgmtDoorSetAttr {
    cmd: DlmgmtCmd,
    conf_id: u32,
    attr: [u8; MAXLINKATTRLEN],
    attr_sz: u32,
    typ: DlmgmtDoorAttrType,
    val: [u8; MAXLINKATTRVALLEN],
}

#[repr(C)]
struct DlmgmtDoorUnsetAttr {
    cmd: DlmgmtCmd,
    conf_id: u32,
    attr: [u8; MAXLINKATTRLEN],
}

#[repr(C)]
struct DlmgmtDoorDestroyConf {
    cmd: DlmgmtCmd,
    conf_id: u32,
}

//TODO this is coming back once i get around to persistent confi
#[allow(dead_code)]
pub(crate) fn connect_simnet_peers(
    link_id_a: u32,
    link_id_b: u32,
) -> Result<(), Error> {
    let peer_info = get_link(link_id_b)?;

    let key = "simnetpeer";

    let f = dlmgmt_door_fd()?;

    // open configuration
    let open_request = DlmgmtDoorOpenConf {
        cmd: DlmgmtCmd::OpenConf,
        linkid: link_id_a,
    };

    let open_response: DlmgmtOpenConfRetval =
        door_call(f.as_raw_fd(), open_request);
    if open_response.err != 0 {
        return Err(Error::Dlmgmtd(format!(
            "openconf failed: {}",
            open_response.err
        )));
    }
    if open_response.conf_id == 0 {
        return Err(Error::Dlmgmtd("open conf returned confid 0".into()));
    }
    let conf_id = open_response.conf_id;
    debug!("got confid {}", conf_id);

    // clear previous value
    let mut clear_request = DlmgmtDoorUnsetAttr {
        cmd: DlmgmtCmd::UnsetAttr,
        conf_id,
        attr: [0; MAXLINKATTRLEN],
    };
    for (i, c) in key.chars().enumerate() {
        clear_request.attr[i] = c as u8;
    }
    let clear_response: DlmgmtRetval = door_call(f.as_raw_fd(), clear_request);
    if clear_response.err != 0 {
        close_conf(f.as_raw_fd(), conf_id)?;
        return Err(Error::Dlmgmtd(format!(
            "clear conf failed: {}",
            open_response.err
        )));
    }

    debug!("setting peer={} for link id {}", peer_info.name, link_id_a);

    // set attribute
    let mut set_request = DlmgmtDoorSetAttr {
        cmd: DlmgmtCmd::SetAttr,
        conf_id,
        attr: [0; MAXLINKATTRLEN],
        attr_sz: (peer_info.name.len() + 1) as u32,
        typ: DlmgmtDoorAttrType::Str,
        val: [0; MAXLINKATTRVALLEN],
    };
    for (i, c) in key.chars().enumerate() {
        set_request.attr[i] = c as u8;
    }
    for (i, b) in peer_info.name.chars().enumerate() {
        set_request.val[i] = b as u8;
    }
    let set_response: DlmgmtRetval = door_call(f.as_raw_fd(), set_request);
    if set_response.err != 0 {
        close_conf(f.as_raw_fd(), conf_id)?;
        return Err(Error::Dlmgmtd(format!(
            "set conf attr failed: {}",
            set_response.err
        )));
    }

    // write new config
    let write_request = DlmgmtDoorWriteConf {
        cmd: DlmgmtCmd::WriteConf,
        conf_id,
    };
    let write_response: DlmgmtRetval = door_call(f.as_raw_fd(), write_request);
    if write_response.err != 0 {
        close_conf(f.as_raw_fd(), conf_id)?;
        return Err(Error::Dlmgmtd(format!(
            "write conf failed: {}",
            write_response.err
        )));
    }

    // close conf
    close_conf(f.as_raw_fd(), conf_id)?;

    Ok(())
}

fn close_conf(fd: i32, conf_id: u32) -> Result<(), Error> {
    let close_request = DlmgmtDoorDestroyConf {
        cmd: DlmgmtCmd::DestroyConf,
        conf_id,
    };
    let close_response: DlmgmtRetval = door_call(fd, close_request);
    if close_response.err != 0 {
        return Err(Error::Dlmgmtd(format!(
            "close conf failed: {}",
            close_response.err
        )));
    }
    Ok(())
}

pub(crate) fn create_simnet_link(
    name: &str,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    let id = crate::link::create_link_id(name, LinkClass::Simnet, flags)?;
    let link_info = crate::ioctl::create_simnet(id, flags)?;
    if (flags as u32 & LinkFlags::Persistent as u32) != 0 {
        //TODO
        //save_simnet(name, flags)?;
    }

    Ok(link_info)
}

pub fn create_vnic_link(
    name: &str,
    link: u32,
    flags: LinkFlags,
) -> Result<LinkInfo, Error> {
    let id = crate::link::create_link_id(name, LinkClass::Vnic, flags)?;
    let link_info = crate::ioctl::create_vnic(id, link)?;
    if (flags as u32 & LinkFlags::Persistent as u32) != 0 {
        //TODO
        //save_simnet(name, flags)?;
    }

    Ok(link_info)
}

pub struct DlmgmtGetLinkId {
    pub cmd: DlmgmtCmd,
    pub name: [u8; crate::sys::MAXLINKNAMELEN as usize],
}

pub fn linkname_to_id(name: &str) -> Result<u32, Error> {
    let mut request = DlmgmtGetLinkId {
        cmd: DlmgmtCmd::GetLinkId,
        name: [0; crate::sys::MAXLINKNAMELEN as usize],
    };
    for (i, c) in name.chars().enumerate() {
        request.name[i] = c as u8;
    }

    let f = dlmgmt_door_fd()?;

    let response: DlmgmtLinkRetval = door_call(f.as_raw_fd(), request);
    if response.err == (ENOENT as u32) || response.linkid == 0 {
        return Err(Error::NotFound(format!("link {} not found", name)));
    }
    if response.err != 0 {
        return Err(Error::Dlmgmtd(format!("get linkid: {}", response.err)));
    }

    Ok(response.linkid)
}

/* TODO
pub(crate) fn save_simnet(_name: &String, _flags: LinkFlags) -> Result<(), Error> {
    Err(Error::NotImplemented)
}
*/

pub(crate) fn delete_link(id: u32, flags: LinkFlags) -> Result<(), Error> {
    // delete the active link
    let link = match get_link(id) {
        Err(Error::NotFound(_)) => return Ok(()),
        Err(e) => return Err(e),
        Ok(link) => link,
    };
    if let Err(err) = match link.class {
        LinkClass::Simnet => crate::ioctl::delete_simnet(id),
        LinkClass::Vnic => crate::ioctl::delete_vnic(id),
        _ => Err(Error::NotImplemented),
    } {
        warn!("class-specific delete error: {}", err);
        return Err(err);
    }

    if let Err(e) = delete_link_id(id, flags) {
        warn!("failed to delete link: {}", e);
        return Err(e);
    }

    // TODO delete the persistent link
    Ok(())
}

#[derive(Debug)]
#[repr(C)]
pub enum Bool {
    False,
    True,
}

#[derive(Debug)]
#[repr(C)]
pub struct DlmgmtDoorCreateId {
    pub cmd: u32,
    pub link: [u8; crate::sys::MAXLINKNAMELEN as usize],
    pub class: u32,
    pub media: u32,
    pub prefix: Bool,
    pub flags: u32,
}

fn dlmgmt_door_fd() -> Result<File, Error> {
    File::open("/etc/svc/volatile/dladm/dlmgmt_door").map_err(Error::Io)
}

pub fn create_link_id(
    name: &str,
    class: LinkClass,
    flags: LinkFlags,
) -> Result<u32, Error> {
    let f = dlmgmt_door_fd()?;

    let mut link = [0u8; crate::sys::MAXLINKNAMELEN as usize];
    if name.len() >= crate::sys::MAXLINKNAMELEN as usize {
        return Err(Error::BadArgument(format!(
            "link name must be less than {} characters",
            crate::sys::MAXLINKNAMELEN,
        )));
    }
    for (i, c) in name.chars().enumerate() {
        link[i] = c as u8;
    }

    let request = DlmgmtDoorCreateId {
        cmd: crate::link::DlmgmtCmd::CreateLinkId as u32,
        link,
        class: class as u32,
        media: crate::sys::DL_ETHER,
        prefix: Bool::False,
        flags: flags as u32,
    };

    let response: DlmgmtLinkRetval = door_call(f.as_raw_fd(), request);
    if response.linkid == 0 || response.err != 0 {
        return Err(Error::Dlmgmtd(format!(
            "link id creation failed: {}",
            response.err
        )));
    }

    Ok(response.linkid)
}

#[repr(C)]
struct DlmgmtDoorDestroyId {
    cmd: u32,
    id: u32,
    flags: u32,
}

pub fn delete_link_id(id: u32, flags: LinkFlags) -> Result<(), Error> {
    let f = dlmgmt_door_fd()?;

    let request = DlmgmtDoorDestroyId {
        cmd: crate::link::DlmgmtCmd::DestroyLinkId as u32,
        id,
        flags: flags as u32,
    };

    let response: DlmgmtLinkRetval = door_call(f.as_raw_fd(), request);
    if response.err != 0 {
        return Err(Error::Dlmgmtd(format!(
            "link id delete failed: {}",
            response.err
        )));
    }

    Ok(())
}
