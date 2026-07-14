#![allow(non_camel_case_types)]
#![allow(dead_code)]

const SHB_BLOCK_MAGIC : [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
const SHB_BYTE_ORDER_MAGIC_BE : [u8; 4] = [0x4D, 0x3C, 0x2B, 0x1A];
const SHB_BYTE_ORDER_MAGIC_LE : [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];

const SHB_OP_HW : u32 = 2;
const SHB_OP_OS : u32 = 3;
const SHB_OP_USER_APP : u32 = 4;

struct pcapng_shb {
    block_type          : u32,
    total_len           : u32,
    byte_order_magic    : u32,
    major_version       : u16,
    minor_version       : u16,
    section_len         : u64,
}

impl pcapng_shb {
    fn new() -> Self {
        Self {
            block_type          : 0,
            total_len           : 0,
            byte_order_magic    : 0,
            major_version       : 0,
            minor_version       : 0,
            section_len         : 0,
        }
    }
}

struct pcapng_shb_opt_hw {
    opt_type    : u16,
    opt_len     : u16,
    opt_data    : Vec<u8>,
}

pub struct pcapng {
    handle  : i32,
    shb_hdr : pcapng_shb,
    pkt_buffer : [u8; 4096],
    big_endian : bool,
}

impl pcapng {
    pub fn new() -> Self {
        Self {
            handle  : -1,
            shb_hdr : pcapng_shb::new(),
            pkt_buffer : [0; 4096],
            big_endian : false,
        }
    }

    pub fn open(&mut self, filename : String) -> i32 {
        unsafe {
            self.handle = libc::open(filename.as_ptr() as *const i8, libc::O_RDONLY);
            if self.handle == -1 {
                println!("failed to open {}", filename);
                return -1;
            }

            println!("opened {}", filename);

            // read the header
            let res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, 24);
            if res != 24 {
                println!("invalid read length {}", res);
                return -1;
            }

            println!("read 0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}",
                        self.pkt_buffer[0],
                        self.pkt_buffer[1],
                        self.pkt_buffer[2],
                        self.pkt_buffer[3]);

            // validate section header length
            if self.pkt_buffer[..4] != SHB_BLOCK_MAGIC[..4] {
                println!("invalid section header magic");
                return -1;
            }

            self.shb_hdr.total_len =
                (self.pkt_buffer[4] as u32) | ((self.pkt_buffer[5] as u32) << 8) |
                ((self.pkt_buffer[6] as u32) << 16) | ((self.pkt_buffer[7] as u32) << 24);
            println!("total len {}", self.shb_hdr.total_len);

            if self.pkt_buffer[8..12] == SHB_BYTE_ORDER_MAGIC_BE[..4] {
                self.big_endian = true;
                println!("big endian order");
            } else if self.pkt_buffer[8..12] == SHB_BYTE_ORDER_MAGIC_LE[..4] {
                self.big_endian = false;
                println!("little endian order");
            }

            self.shb_hdr.major_version = ((self.pkt_buffer[12] as u16) << 8) | self.pkt_buffer[13] as u16;
            self.shb_hdr.minor_version = ((self.pkt_buffer[14] as u16) << 8) | self.pkt_buffer[15] as u16;

            let section_hdr_bytes : [u8; 8] = self.pkt_buffer[16..24].
                                                    try_into().
                                                    expect("Buffer is shorter than 8 bytes");
            if self.big_endian {
                self.shb_hdr.section_len = u64::from_be_bytes(section_hdr_bytes);
            } else {
                self.shb_hdr.section_len = u64::from_le_bytes(section_hdr_bytes);
            }
        }
        0
    }
}

