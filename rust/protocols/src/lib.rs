pub mod eth;
pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod icmp;
pub mod udp;
pub mod tcp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
