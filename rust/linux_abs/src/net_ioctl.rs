#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::error_codes;

use std::ffi::CString;
use error_codes::netos_error_codes;

pub struct net_ioctl {
}

impl net_ioctl {
    pub fn set_promisc(ifname : &String, fd : i32) -> Option<netos_error_codes> {
        unsafe {
            let mut ifr : libc::ifreq = std::mem::zeroed();
            let name_bytes = ifname.as_bytes();

            if name_bytes.len() > ifr.ifr_name.len() {
                return Some(netos_error_codes::Netos_Error_Invalid_Ifname);
            }

            ifr.ifr_name.fill(0);

            for (dest, &src) in ifr.ifr_name.iter_mut().zip(name_bytes) {
                *dest = src as libc::c_char;
            }

            ifr.ifr_name[name_bytes.len()] = 0;

            let mut ret : i32 = libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr);
            if ret < 0 {
                return Some(netos_error_codes::Netos_Error_Get_IfFlags_Failed);
            }

            let flags = ifr.ifr_ifru.ifru_flags as libc::c_int;
            let promisc = flags | libc::IFF_PROMISC;

            ifr.ifr_ifru = libc::__c_anonymous_ifr_ifru {
                ifru_flags: promisc as libc::c_short,
            };

            ret = libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr);
            if ret != 0 {
                return Some(netos_error_codes::Netos_Error_Set_IfFlags_Failed);
            }
        }

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

