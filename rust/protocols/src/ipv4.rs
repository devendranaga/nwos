#![allow(non_camel_case_types)]

use std::fmt;

use crate::pkt_buffer;

pub struct ipv4_hdr {
    pub version         : u8, // 4 bits
    pub header_len      : u8, // 4 bits
    pub dscp            : u8, // 6 bits
    pub ecn             : u8, // 2 bits
    pub total_len       : u16,
    pub id              : u16,
    pub reserved        : u8,
    pub dont_frag       : u8,
    pub more_frag       : u8,
    pub frag_off        : u32,
    pub ttl             : u8,
    pub protocol        : u8,
    pub hdr_chksum      : u16,
    pub src_ipaddr      : u32,
    pub dst_ipaddr      : u32
}

impl std::fmt::Display for ipv4_hdr {
    fn fmt(&self, f : &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "IPv4: ")?;
        writeln!(f, "\t version: {}", self.version)?;
        writeln!(f, "\t header_len: {}", self.header_len)?;
        writeln!(f, "\t dscp: {}", self.dscp)?;
        writeln!(f, "\t ecn: {}", self.ecn)?;
        writeln!(f, "\t total_len: {}", self.total_len)?;
        writeln!(f, "\t id: {}", self.id)?;
        writeln!(f, "\t reserved: {}", self.reserved)?;
        writeln!(f, "\t dont_frag: {}", self.dont_frag)?;
        writeln!(f, "\t more_frag: {}", self.more_frag)?;
        writeln!(f, "\t frag_off: {}", self.frag_off)?;
        writeln!(f, "\t ttl: {}", self.ttl)?;
        writeln!(f, "\t protocol: {}", self.protocol)?;
        writeln!(f, "\t hdr_chksum: {}", self.hdr_chksum)?;
        writeln!(f, "\t src_ipaddr: {:08x}", self.src_ipaddr)?;
        write!(f, "\t dst_ipaddr: {:08x}", self.dst_ipaddr)
    }
}

impl ipv4_hdr {
    pub fn new() -> Self {
        Self {
            version     : 0,
            header_len  : 0,
            dscp        : 0,
            ecn         : 0,
            total_len   : 0,
            id          : 0,
            reserved    : 0,
            dont_frag   : 0,
            more_frag   : 0,
            frag_off    : 0,
            ttl         : 0,
            protocol    : 0,
            hdr_chksum  : 0,
            src_ipaddr  : 0,
            dst_ipaddr  : 0
        }
    }

    pub fn decode(&mut self, pkt_buf : &mut pkt_buffer::netos_pkt_buffer) -> i32 {
        self.version = (pkt_buf.buffer[pkt_buf.offset] & 0xF0) >> 4;
        self.header_len = (pkt_buf.buffer[pkt_buf.offset] & 0x0F) * 5;
        pkt_buf.offset += 1;

        self.dscp = (pkt_buf.buffer[pkt_buf.offset] & 0xFC) >> 2;
        self.ecn = pkt_buf.buffer[pkt_buf.offset] & 0x03;

        0
    }
}

