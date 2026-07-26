pub mod pcapng;
pub mod pcap;

#[cfg(test)]
mod tests {
    use super::*;
    use pcapng;
    use pcap;

    fn read_epb_callback(epb : &mut pcapng::enhanced_pkt_block) {
        println!("Enhanced Packet Block:");
        println!("\tCaptured packet Length: {}", epb.captured_len);
        println!("\tOriginal packet Length: {}", epb.original_len);
        println!("\tPacket Length: {}", epb.packet_data.len());
    }

    fn read_spb_callback(spb : &mut pcapng::simple_pkt_block) {
        println!("Simple Packet Block:");
        println!("\tOriginal packet Length: {}", spb.original_len);
        println!("\tPacket Length: {}", spb.packet_data.len());
    }

    #[test]
    fn test_pcapng_no_options() {
        let mut p_handle = pcapng::pcapng_parser::new();
        let res = p_handle.parse("tests/test_no_options.pcapng".to_string(),
                                 read_epb_callback,
                                 read_spb_callback);
        if res != 0 {
            panic!("invalid pcapng file");
        }
        println!("test pcapng ok\n");
        p_handle.close();
    }

    static mut count :u32 = 1;

    fn read_pcap_callback(pkt : &mut pcap::netos_pcap_packet_header) {

        unsafe {
            println!("read callback called {} {}", count, pkt.incl_len);
            count += 1;
        }
    }

    #[test]
    fn test_pcap() {
        let mut p_handle_1 = pcap::netos_pcap_parser::new();
        let ret = p_handle_1.read("tests/tcp.pcap".to_string(),
                                  read_pcap_callback);
        if ret != 0 {
            panic!("failed to open pcap file");
            return;
        }

        println!("test pcap ok\n");
    }
}
