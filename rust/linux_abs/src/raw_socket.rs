#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::net_ioctl;
use crate::error_codes;
use error_codes::netos_error_codes;

pub struct raw_socket {
    ifname : String,
    pub fd : i32,
    ifindex : u32,
    mac : [u8; 6],
}

impl raw_socket {
    pub fn new() -> raw_socket {
        raw_socket {
            ifname : String::new(),
            fd : -1,
            ifindex : 0,
            mac : [0; 6]
        }
    }

    pub fn create(&mut self, device_name: & String) -> Option<netos_error_codes> {
        unsafe {
            // create the raw socket
            self.fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL);
            if self.fd < 0 {
                return Some(netos_error_codes::Netos_Error_Raw_Sock_Create_Failure);
            }
        }

        // setup promiscuous mode of operation
        let mut err = net_ioctl::net_ioctl::modify_promisc(device_name, self.fd, true);
        match err {
            Some(netos_error_codes::Netos_Error_No_Error) => {
                // get interface index
                let res = net_ioctl::net_ioctl::get_ifindex(device_name, self.fd);
                match res {
                    Ok(value) => self.ifindex = value,
                    Err(err) => { return Some(err); }
                }
            },
            _ => {
                return err;
            }
        }

        // get the interface mac address
        err = net_ioctl::net_ioctl::get_mac_addr(device_name, self.fd, &mut self.mac);
        match err {
            Some(netos_error_codes::Netos_Error_No_Error) => {
                // copy device name
                self.ifname = device_name.clone();
            },
            _ => {
                return err;
            }
        }


        return Some(netos_error_codes::Netos_Error_No_Error);
    }

    pub fn close(fd : i32) {
        unsafe { libc::close(fd); }
    }
}

pub struct socket {
    raw : raw_socket
}

impl socket {
}
