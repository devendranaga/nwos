#![allow(non_camel_case_types)]

pub mod error_codes;
pub mod net_ioctl;
pub mod raw_socket;

#[cfg(test)]
mod tests {
    use super::*;
    use raw_socket::socket;
    use net_ioctl::net_ioctl;
    use error_codes::netos_error_codes;

    #[test]
    fn test_promisc() {
        let ifname = String::from("dummy0");
        let fd = socket::create_raw();

        if fd < 0 {
            panic!("cannot open raw socket");
        }
        let val = net_ioctl::modify_promisc(&ifname, fd, true);
        match val {
            Some(netos_error_codes::Netos_Error_No_Error) => {
                println!("set promisc ok");
            },
            _ => {
                panic!("cannot set promiscous mode on {}", ifname);
            }
        }
    }
}
