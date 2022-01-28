// Copyright 2021 Oxide Computer Company

use crate::sys;
use crate::Error;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

pub fn get_linkstate(name: &str) -> Result<sys::link_state_t, Error> {
    unsafe {
        // open kstat
        let kcp = sys::kstat_open();
        if kcp.is_null() {
            return Err(Error::Kstat("open".to_string()));
        }

        let module = CString::new("link").expect("cstring link");
        let cname = CString::new(name).expect("cstring link name");
        let stat = CString::new("link_state").expect("cstring link_state");

        // lookup the kstat module/instance
        let ksp = sys::kstat_lookup(
            kcp,
            module.as_c_str().as_ptr() as *mut c_char,
            0,
            cname.as_c_str().as_ptr() as *mut c_char,
        );
        if ksp.is_null() {
            sys::kstat_close(kcp);
            return Err(Error::Kstat(format!("lookup {}", name)));
        }

        // read the kstat module/instance
        if sys::kstat_read(kcp, ksp, ptr::null_mut()) == -1 {
            sys::kstat_close(kcp);
            return Err(Error::Kstat("read".to_string()));
        }

        // lookup the link state data value
        let knp = sys::kstat_data_lookup(
            ksp,
            stat.as_c_str().as_ptr() as *mut c_char,
        ) as *mut sys::kstat_named_t;

        if knp.is_null() {
            sys::kstat_close(kcp);
            return Err(Error::Kstat("data lookup".to_string()));
        }

        if (*knp).data_type != sys::KSTAT_DATA_UINT32 as u8 {
            sys::kstat_close(kcp);
            return Err(Error::Kstat("expected u32".to_string()));
        }

        sys::kstat_close(kcp);
        Ok((*knp).value.ui32 as sys::link_state_t)
    }
}
