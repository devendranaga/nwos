#![allow(non_camel_case_types)]

pub struct netos_pkt_buffer {
    pub buffer : [u8; 4096 * 16],
    pub offset : usize,
    pub rx_len : usize,
}

impl netos_pkt_buffer {
    pub fn new() -> Self {
        Self {
            buffer : [0; 4096 * 16],
            offset : 0,
            rx_len : 0,
        }
    }

    pub fn has_short_len(&mut self) -> bool {
        self.offset >= self.rx_len
    }

    pub fn decode_2_bytes(&mut self) -> u16 {
        let u16_val = ((self.buffer[self.offset] as u16) << 8) |
                       (self.buffer[self.offset + 1]) as u16;
        self.offset += 2;

        u16_val
    }

    pub fn encode_2_bytes(&mut self, val : u16) {
        self.buffer[self.offset]        = ((val & 0xFF00) >> 8) as u8;
        self.buffer[self.offset + 1]    = (val & 0x00FF) as u8;
    }

    pub fn encode_4_bytes(&mut self, val : u32) {
        self.buffer[self.offset]        = ((val & 0xFF000000) >> 24) as u8;
        self.buffer[self.offset + 1]    = ((val & 0x00FF0000) >> 16) as u8;
        self.buffer[self.offset + 2]    = ((val & 0x0000FF00) >> 8) as u8;
        self.buffer[self.offset + 3]    = (val & 0x000000FF) as u8;
    }

    pub fn decode_4_bytes(&mut self) -> u32 {
        let u32_val = (((self.buffer[self.offset] as u32) << 24) |
                       ((self.buffer[self.offset + 1] as u32) << 16) |
                       ((self.buffer[self.offset + 2] as u32) << 8) |
                       ((self.buffer[self.offset + 3] as u32)));
        self.offset += 4;

        u32_val
    }
    pub fn decode_macaddr(&mut self, mac_ptr : &mut [u8; 6]) {
        mac_ptr[0] = self.buffer[self.offset];
        mac_ptr[1] = self.buffer[self.offset] + 1;
        mac_ptr[2] = self.buffer[self.offset] + 2;
        mac_ptr[3] = self.buffer[self.offset] + 3;
        mac_ptr[4] = self.buffer[self.offset] + 4;
        mac_ptr[5] = self.buffer[self.offset] + 5;

        self.offset += 6;
    }

    pub fn set_len(&mut self, len : usize) { self.rx_len = len; }
}

