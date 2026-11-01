#![allow(non_camel_case_types)]

pub mod error_codes;
pub mod net_ioctl;
pub mod raw_socket;

#[cfg(test)]
mod tests {
    use super::*;
    use net_ioctl::net_ioctl;
    use error_codes::netos_error_codes;

    #[test]
    fn test_promisc() {
        let ifname = String::from("dummy0");
        let mut raw = raw_socket::raw_socket::new();

        let ret = raw.create(&ifname);
        match ret {
            Some(netos_error_codes::Netos_Error_No_Error) => {
                println!("got socket : {}", raw.fd);
            },
            _ => {
                panic!("cannot get raw socket... possible non-root mode");
            }
        }

        if raw.fd < 0 {
            panic!("cannot open raw socket!");
        }
        let val = net_ioctl::modify_promisc(&ifname, raw.fd, true);
        match val {
            Some(netos_error_codes::Netos_Error_No_Error) => {
                println!("set promisc ok");
            },
            _ => {
                panic!("cannot set promiscous mode on {}", ifname);
            }
        }
        let mut mac : [u8; 6] = [0; 6];

        let val = net_ioctl::get_mac_addr(&ifname, raw.fd, &mut mac);
        match val {
            Some(netos_error_codes::Netos_Error_No_Error) => {
                println!("mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            },
            _=> {
                panic!("cannot get mac address on {}", ifname);
            }
        }
    }
}
