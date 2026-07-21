#![allow(non_camel_case_types)]

#[path = "pkt_buffer.rs"]
pub mod pkt_buffer;

use pkt_buffer::netos_pkt_buffer;

pub struct eth_hdr {
    pub dst : [u8; 6],
    pub src : [u8; 6],
    pub ethertype : u16,
}

impl eth_hdr {
    pub fn new() -> Self {
        Self {
            dst : [0; 6],
            src : [0; 6],
            ethertype : 0,
        }
    }

    pub fn decode(&mut self, buf : &mut netos_pkt_buffer) -> i32 {
        buf.decode_macaddr(&mut self.dst);
        buf.decode_macaddr(&mut self.src);
        self.ethertype = buf.decode_2_bytes();

        0
    }
}
