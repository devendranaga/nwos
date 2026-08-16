#![allow(unused_imports)]

use clap::{Arg, ArgAction, Command};
use pcapng::pcap;
use protocols::pkt_buffer::netos_pkt_buffer;
use protocols::eth;
use protocols::arp;
use protocols::ipv4;
use protocols::icmp;
use protocols::udp;
use protocols::tcp;
use protocols::icmp6;

fn netos_pktdump_parse_frame(pkt : &mut pcap::netos_pcap_packet_header) {
    let mut pkt_buf = netos_pkt_buffer::new();
    let mut i = 0;

    while i < pkt.incl_len as usize {
        pkt_buf.buffer[i] = pkt.packet_data[i];
        i += 1;
    }

    pkt_buf.offset = 0;
    pkt_buf.rx_len = pkt.incl_len as usize;

    let mut eth_hdr = eth::eth_hdr::new();
    let mut ret = eth_hdr.decode(&mut pkt_buf);
    if ret != 0 {
        return;
    }

    // match ethertype
    match eth_hdr.ethertype {
        eth::NETOS_ETHERTYPE_IPV4 => {
            let mut ipv4_hdr = ipv4::ipv4_hdr::new();

            ret = ipv4_hdr.decode(&mut pkt_buf);
            if ret != 0 {
                return;
            }
        },
        eth::NETOS_ETHERTYPE_ARP => {
            let mut arp_hdr = arp::arp_hdr::new();

            ret = arp_hdr.decode(&mut pkt_buf);
            if ret != 0 {
                return;
            }
        },
        _ => ()
    }
}

fn netos_pktdump_read_callback(pkt : &mut pcap::netos_pcap_packet_header) {
    netos_pktdump_parse_frame(pkt);
}

fn netos_pktdump_pcapfile_parse(filename : &String) {
    let mut pcap_parser = pcap::netos_pcap_parser::new();
    let ret = pcap_parser.read(filename.to_string(), netos_pktdump_read_callback);
    if ret != 0 {
        println!("invalid pcap file format in {}", filename);
    }
}

fn main() {
    let matches = Command::new("pktdump")
                    .version("1.0.0")
                    .author("Devendra Naga")
                    .about("xyz")
                    .arg(
                        Arg::new("pcap filename")
                            .short('p')
                            .long("pcapfile")
                            .value_name("FILE")
                            .help("PCAP file path")
                            .default_value("")
                    )
                    .get_matches();

    let pcap_filename = matches.get_one::<String>("pcap filename").unwrap();

    if pcap_filename != "" {
        println!("pcapfile : {}", pcap_filename);
        netos_pktdump_pcapfile_parse(&pcap_filename);
    }
}

