#![allow(non_camel_case_types)]
#![allow(dead_code)]

#[path = "error_codes.rs"]
pub mod error_codes;

use std::mem;
use std::ffi::CString;
use error_codes::netos_error_codes;

struct net_ioctl {
}

impl net_ioctl {
    pub fn set_promisc(ifname : String, fd : i32) -> Option<netos_error_codes> {
        let ifname_str = CString::new(ifname).unwrap();
        let ifname_ptr = ifname_str.as_ptr();

        return Some(netos_error_codes::Netos_Error_No_Error);
    }

    pub fn get_ifindex(ifname : String, fd : i32) -> Result<u32, netos_error_codes> {
        let ifname_str = CString::new(ifname).unwrap();
        let ifname_ptr = ifname_str.as_ptr();

        unsafe {
            let ifindex = libc::if_nametoindex(ifname_ptr);
            if ifindex == 0 {
                return Err(netos_error_codes::Netos_Error_Invalid_Ifname);
            }
            Ok(ifindex)
        }

    }
}
