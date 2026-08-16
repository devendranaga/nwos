#![allow(non_camel_case_types)]

pub struct netos_checksum<'chksum> {
    buffer : &'chksum [u8],
    len : u32,
}

