#![allow(non_camel_case_types)]
#![allow(dead_code)]

pub struct raw_socket {
    fd : i32
}

impl raw_socket {
    pub fn new() -> raw_socket {
        raw_socket {
            fd : -1
        }
    }

    pub fn create(&mut self, device_name: & String) -> i32 {
        unsafe {
            self.fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL);
        }

        0
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
