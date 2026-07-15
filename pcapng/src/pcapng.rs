#![allow(non_camel_case_types)]
#![allow(dead_code)]

// constants
const SHB_BLOCK_MAGIC           : [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
const SHB_BYTE_ORDER_MAGIC_BE   : [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];
const SHB_BYTE_ORDER_MAGIC_LE   : [u8; 4] = [0x4D, 0x3C, 0x2B, 0x1A];

const SHB_OP_COMMENT    : u16 = 1;
const SHB_OP_HW         : u16 = 2;
const SHB_OP_OS         : u16 = 3;
const SHB_OP_USER_APP   : u16 = 4;

const SHB_OPT_COMMENT   : u32 = 0x00000001;
const SHB_OPT_HW        : u32 = 0x00000002;
const SHB_OPT_OS        : u32 = 0x00000004;
const SHB_OPT_USER_APP  : u32 = 0x00000008;

/// SHB header
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

pub struct pcapng {
    handle          : i32,
    shb_hdr         : pcapng_shb,
    pkt_buffer      : [u8; 4096],
    shb_opts        : u32,
    hw              : Vec<u8>,
    os              : Vec<u8>,
    application     : Vec<u8>,
    comment         : Vec<u8>,
    big_endian      : bool,
    offset          : usize,
}

impl pcapng {
    pub fn new() -> Self {
        Self {
            handle          : -1,
            shb_hdr         : pcapng_shb::new(),
            pkt_buffer      : [0; 4096],
            shb_opts        : 0,
            hw              : Vec::new(),
            os              : Vec::new(),
            application     : Vec::new(),
            comment         : Vec::new(),
            big_endian      : false,
            offset          : 0,
        }
    }

    fn get_u16(&mut self) -> u16 {
        let u16_val : u16;

        if self.big_endian {
            u16_val = ((self.pkt_buffer[self.offset] as u16) << 8) |
                        self.pkt_buffer[self.offset + 1] as u16;
        } else {
            u16_val = ((self.pkt_buffer[self.offset + 1] as u16) << 8) |
                        self.pkt_buffer[self.offset] as u16;
        }
        self.offset += 2;
        return u16_val;
    }

    fn get_u64(&mut self) -> u64 {
        let u64_bytes : [u8; 8] = self.pkt_buffer[16..24].
                                                    try_into().
                                                    expect("Buffer is shorter than 8 bytes");
        let u64_val : u64;

        if self.big_endian {
            u64_val = u64::from_be_bytes(u64_bytes);
        } else {
            u64_val = u64::from_le_bytes(u64_bytes);
        }
        self.offset += 8;
        return u64_val;
    }

    fn parse_options(&mut self) -> i32 {
        let mut option : u16;
        let mut option_len : u16;

        loop {
            unsafe {
                let mut res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, 4);
                if res != 4 {
                    println!("invalid read length {}", res);
                    return -1;
                }

                if (self.pkt_buffer[0] == 0) &&
                   (self.pkt_buffer[1] == 0) &&
                   (self.pkt_buffer[2] == 0) &&
                   (self.pkt_buffer[3] == 0) {
                    println!("end of options reached");
                    return 0;
                }

                self.offset = 0;

                option = self.get_u16();
                option_len = self.get_u16();
                let original_option_len = option_len as usize;

                println!("read options_len {}", option_len);
                if option_len % 4 != 0 {
                    option_len = (option_len + 3) & !3;
                }
                println!("option {} option_len {}", option, option_len);

                self.offset = 0;

                res = libc::read(self.handle, self.pkt_buffer.as_ptr() as *mut libc::c_void, option_len as usize);
                if res != option_len.try_into().unwrap() {
                    println!("invalid read length {}", res);
                    return -1;
                }

                match option {
                    SHB_OP_HW => {
                        self.hw = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_HW;
                    },
                    SHB_OP_OS => {
                        self.os = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_OS;
                    },
                    SHB_OP_USER_APP => {
                        self.application = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_USER_APP;
                    },
                    SHB_OP_COMMENT => {
                        self.comment = self.pkt_buffer[0..original_option_len].to_vec();
                        self.shb_opts |= SHB_OPT_COMMENT;
                    },
                    _ => (),
                }
            }
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

            self.offset = 12;
            self.shb_hdr.major_version = self.get_u16();
            self.shb_hdr.minor_version = self.get_u16();
            self.shb_hdr.section_len = self.get_u64();

            println!("major {} minor {} section header len 0x{:02x}",
                            self.shb_hdr.major_version,
                            self.shb_hdr.minor_version,
                            self.shb_hdr.section_len);

            self.parse_options();
        }
        0
    }
}

