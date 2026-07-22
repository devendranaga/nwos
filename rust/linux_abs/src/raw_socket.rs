#![allow(non_camel_case_types)]
#![allow(dead_code)]

struct socket {

}

impl socket {
    pub fn create_raw() -> i32 {
        unsafe {
            libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL)
        }
    }

    pub fn close(fd : i32) {
        unsafe { libc::close(fd); }
    }
}
