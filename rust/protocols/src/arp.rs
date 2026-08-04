#![allow(non_camel_case_types)]

use crate::pkt_buffer;

use std::fmt;

pub struct arp_hdr {
    pub hw_type                 : u16,
    pub protocol_type           : u16,
    pub hw_addr_len             : u8,
    pub protocol_len            : u8,
    pub op                      : u16,
    pub sender_hwaddr           : [u8; 6],
    pub sender_protocol_addr    : u32,
    pub target_hwaddr           : [u8; 6],
    pub target_protocol_addr    : u32,
}

impl std::fmt::Display for arp_hdr {
    fn fmt(&self, f : &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ARP: ")?;
        writeln!(f, "\t hw_type: {}", self.hw_type)?;
        writeln!(f, "\t protocol_type: {}", self.protocol_type)?;
        writeln!(f, "\t hw_addr_len: {}", self.hw_addr_len)?;
        writeln!(f, "\t protocol_len: {}", self.protocol_len)?;
        writeln!(f, "\t op: {}", self.op)?;
        writeln!(f, "\t sender_hwaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.sender_hwaddr[0], self.sender_hwaddr[1],
                    self.sender_hwaddr[2], self.sender_hwaddr[3],
                    self.sender_hwaddr[4], self.sender_hwaddr[5])?;
        writeln!(f, "\t sender_protocol_addr: {}", self.sender_protocol_addr)?;
        writeln!(f, "\t target_hwaddr: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    self.target_hwaddr[0], self.target_hwaddr[1],
                    self.target_hwaddr[2], self.target_hwaddr[3],
                    self.target_hwaddr[4], self.target_hwaddr[5])?;
        writeln!(f, "\t target_protocol_addr: {}", self.target_protocol_addr)
    }
}

impl arp_hdr {
    pub fn new() -> Self {
        Self {
            hw_type                 : 0,
            protocol_type           : 0,
            hw_addr_len             : 6,
            protocol_len            : 6,
            op                      : 1,
            sender_hwaddr           : [0; 6],
            sender_protocol_addr    : 0,
            target_hwaddr           : [0; 6],
            target_protocol_addr    : 0,
        }
    }

    pub fn decode(&mut self, buf : &mut pkt_buffer::netos_pkt_buffer) -> i32 {
        self.hw_type                = buf.decode_2_bytes();
        self.protocol_type          = buf.decode_2_bytes();
        self.hw_addr_len            = buf.decode_byte();
        self.protocol_len           = buf.decode_byte();
        self.op                     = buf.decode_2_bytes();
        buf.decode_macaddr(&mut self.sender_hwaddr);
        self.sender_protocol_addr   = buf.decode_4_bytes();
        buf.decode_macaddr(&mut self.target_hwaddr);
        self.target_protocol_addr   = buf.decode_4_bytes();

        0
    }
}

