#![allow(non_camel_case_types)]

#[path = "pkt_buffer.rs"]
pub mod pkt_buffer;

use std::fmt;

///
/// Implements an ethernet header
pub struct eth_hdr {
    pub dst : [u8; 6],
    pub src : [u8; 6],
    pub ethertype : u16,
}

impl std::fmt::Display for eth_hdr {
    fn fmt(&self, f : &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Eth: ")?;
        writeln!(f, "\t dst {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                  self.dst[0], self.dst[1], self.dst[2],
                  self.dst[3], self.dst[4], self.dst[5])?;
        writeln!(f, "\t src {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                  self.src[0], self.src[1], self.src[2],
                  self.src[3], self.src[4], self.src[5])?;
        write!(f, "\t ethertype: {:04x}", self.ethertype)
    }
}

impl eth_hdr {
    ///
    /// clears the ethernet header fields
    pub fn new() -> Self {
        Self {
            dst : [0; 6],
            src : [0; 6],
            ethertype : 0,
        }
    }

    ///
    /// decode the ethernet header
    pub fn decode(&mut self, buf : &mut pkt_buffer::netos_pkt_buffer) -> i32 {
        buf.decode_macaddr(&mut self.dst);
        buf.decode_macaddr(&mut self.src);
        self.ethertype = buf.decode_2_bytes();

        0
    }
}

