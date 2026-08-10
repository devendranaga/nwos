#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::ffi::CString;

const NETOS_PCAP_MAGIC_NUMBER_BE : u32 = 0xA1B2C3D4;
const NETOS_PCAP_MAGIC_NUMBER_LE : u32 = 0xD4C3B2A1;

struct netos_pcap_global_header {
    magic           : u32,
    version_major   : u16,
    version_minor   : u16,
    this_zone       : i32,
    sigfigs         : u32,
    snaplen         : u32,
    network         : u32,
}

///
/// Defines pcap packet header
pub struct netos_pcap_packet_header {
    /// timestamp in seconds
    pub ts_sec      : u32,

    /// timestamp in usec
    pub ts_usec     : u32,

    /// captured length
    pub incl_len    : u32,

    /// original length
    pub orig_len    : u32,

    /// packet data
    pub packet_data : Vec<u8>,
}

///
/// Defines the pcap parser interface
pub struct netos_pcap_parser {
    fd : i32
}

fn get_u32(buf : &[u8], offset : usize) -> u32 {
    return ((buf[offset + 3] as u32) << 24)      |
           ((buf[offset + 2] as u32) << 16)  |
           ((buf[offset + 1] as u32) << 8)   |
           (buf[offset]) as u32;
}

impl netos_pcap_global_header {
    fn new() -> Self {
        Self {
            magic           : 0,
            version_major   : 0,
            version_minor   : 0,
            this_zone       : 0,
            sigfigs         : 0,
            snaplen         : 0,
            network         : 0
        }
    }

    fn read(&mut self, fd : i32) -> i32 {
        unsafe {
            let buf : [u8; 24] = [0; 24];

            let ret = libc::read(fd, buf.as_ptr() as *mut libc::c_void, 24);
            if ret != 24 {
                println!("invalid read value");
                return -1;
            }

            self.magic = get_u32(&buf, 0);

            if self.magic != NETOS_PCAP_MAGIC_NUMBER_BE &&
               self.magic != NETOS_PCAP_MAGIC_NUMBER_LE {
                return -1;
            }
        }
        0
    }
}

impl netos_pcap_packet_header {
    pub fn new() -> Self {
        Self {
            ts_sec      : 0,
            ts_usec     : 0,
            incl_len    : 0,
            orig_len    : 0,
            packet_data : Vec::new()
        }
    }
}

///
/// PCAP parser
impl netos_pcap_parser {
    ///
    /// clear the netos_pcap_parser items
    pub fn new() -> Self {
        Self {
            fd : -1
        }
    }

    ///
    /// Reads the packets and calls the user's callback
    ///
    /// Example:
    ///
    /// ```
    ///
    /// use pcapng::pcap;
    ///
    /// fn read_pcap_callback(pkt : &mut pcap::netos_pcap_packet_header) {
    ///     println!("recieved packet length {}", pkt.incl_len);
    /// }
    ///
    /// let mut pcap_handle = pcap::netos_pcap_parser::new();
    /// let ret = pcap_handle.read("./test/tcp.pcap".to_string(), read_pcap_callback);
    /// if ret != 0 {
    ///     println!("invalid capture data\n");
    /// }
    /// ```
    pub fn read(&mut self,
                filename : String,
                read_callback : fn(pkt : &mut netos_pcap_packet_header)) -> i32 {

        let path_libc = CString::new(filename).expect("Cstring::new failed");
        let mut pcap_gl_hdr = netos_pcap_global_header::new();
        let mut offset;

        unsafe {
            self.fd = libc::open(path_libc.as_ptr(), libc::O_RDONLY);
            if self.fd == -1 {
                println!("failed to open {}", path_libc.to_string_lossy());
                return -1;
            }

            // drop if global header signature does not match
            let ret = pcap_gl_hdr.read(self.fd);
            if ret != 0 {
                println!("invalid PCAP global header\n");
                libc::close(self.fd);
                return -1;
            }

            loop {
                let buf : [u8; 4096 * 16] = [0; 4096 * 16];

                offset = 0;

                let mut pcap_hdr = netos_pcap_packet_header::new();
                let mut ret = libc::read(self.fd, buf.as_ptr() as *mut libc::c_void, 16);
                if ret != 16 {
                    if ret == 0 {
                        return 0;
                    }

                    println!("invalid read header\n");
                    return -1;
                }

                pcap_hdr.ts_sec     = get_u32(&buf, offset);
                offset += 4;

                pcap_hdr.ts_usec    = get_u32(&buf, offset);
                offset += 4;

                pcap_hdr.incl_len   = get_u32(&buf, offset);
                offset += 4;

                pcap_hdr.orig_len   = get_u32(&buf, offset);

                if pcap_hdr.incl_len as usize > buf.len() {
                    println!("incl_len is too big {} > buf.len() {}", pcap_hdr.incl_len, buf.len());
                    return -1;
                }
                ret = libc::read(self.fd, buf.as_ptr() as *mut libc::c_void, pcap_hdr.incl_len as usize);
                if ret == 0 {
                    return 0;
                }
                if ret != pcap_hdr.incl_len as isize {
                    println!("invalid read header\n");
                    return -1;
                }

                pcap_hdr.packet_data.extend_from_slice(
                            &buf[0..pcap_hdr.incl_len as usize]);
                read_callback(&mut pcap_hdr);
            }
        }
    }
}

impl Drop for netos_pcap_parser {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd); }
            self.fd = -1;
        }
    }
}

