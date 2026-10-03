#!/usr/bin/python3

import sys
from pkt_buffer import *

NETOS_PCAP_GLOB_HDR_LEN     = 24
NETOS_PCAP_REC_HDR_LEN      = 16
NETOS_PCAP_VER_MAGIC_LE_1   = 0xD4C3B2A1
NETOS_PCAP_VER_MAGIC_LE_2   = 0x4D3CB2A1
NETOS_PCAP_VER_MAGIC_BE_1   = 0xA1B2C3D4
NETOS_PCAP_VER_MAGIC_BE_2   = 0xA1B23C4D
NETOS_PCAP_VER_MAJOR        = 2
NETOS_PCAP_VER_MINOR        = 4

class netos_pcap_glob_hdr:
    def __init__(self):
        self.magic          = 0
        self.version_major  = 0
        self.version_minor  = 0
        self.thiszone       = 0
        self.sigfigs        = 0
        self.snaplen        = 0
        self.network        = 0
        self.endian         = netos_endian.Big

    def parse(self, byte_data):
        pkt_buf = netos_pkt_buffer()
        pkt_buf.set_rx_buf(byte_data)

        self.magic          = pkt_buf.get_4_bytes()
        if self.magic == NETOS_PCAP_VER_MAGIC_LE_1 or\
            self.magic == NETOS_PCAP_VER_MAGIC_LE_2:
            self.endian = netos_endian.Little
        elif self.magic == NETOS_PCAP_VER_MAGIC_BE_1 or\
            self.magic == NETOS_PCAP_VER_MAGIC_BE_2:
            self.endian = netos_endian.Big
        else:
            return False

        self.version_major  = pkt_buf.get_2_bytes_endian(self.endian)
        if self.version_major != NETOS_PCAP_VER_MAJOR:
            return False

        self.version_minor  = pkt_buf.get_2_bytes_endian(self.endian)
        if self.version_minor != NETOS_PCAP_VER_MINOR:
            return False

        self.thiszone       = pkt_buf.get_4_bytes_endian(self.endian)
        self.sigfigs        = pkt_buf.get_4_bytes_endian(self.endian)
        self.snaplen        = pkt_buf.get_4_bytes_endian(self.endian)
        self.network        = pkt_buf.get_4_bytes_endian(self.endian)

        return True

    def print(self):
        print("Global header:")
        print("\t magic: " + str(hex(self.magic)))
        print("\t version_major: " + str(self.version_major))
        print("\t version_minor: " + str(self.version_minor))
        print("\t thiszone: " + str(self.thiszone))
        print("\t sigfigs: " + str(self.sigfigs))
        print("\t snaplen: " + str(self.snaplen))
        print("\t network: " + str(self.network))

class netos_pcap_record:
    def __init__(self):
        self.ts_sec     = 0
        self.ts_usec    = 0
        self.incl_len   = 0
        self.orig_len   = 0

    def parse(self, fd, endian):
        byte_data = fd.read(NETOS_PCAP_REC_HDR_LEN)
        if not byte_data:
            return None

        pkt_buf = netos_pkt_buffer()
        pkt_buf.set_rx_buf(byte_data)

        self.ts_sec     = pkt_buf.get_4_bytes_endian(endian)
        self.ts_usec    = pkt_buf.get_4_bytes_endian(endian)
        self.incl_len   = pkt_buf.get_4_bytes_endian(endian)
        self.orig_len   = pkt_buf.get_4_bytes_endian(endian)

        packet_data = fd.read(self.incl_len)
        if not packet_data:
            return None

        return bytearray(packet_data)

    def print(self):
        print("Record:")
        print("\t ts_sec: " + str(self.ts_sec))
        print("\t ts_usec: " + str(self.ts_usec))
        print("\t incl_len: " + str(self.incl_len))
        print("\t orig_len: " + str(self.orig_len))

class netos_pcap_context:
    def __init__(self):
        self.fd         = -1
        self.glob_hdr   = netos_pcap_glob_hdr()
        self.offset     = 0

    def __del__(self):
        self.fd.close()

    def open_file(self, filename):
        self.fd = open(filename, 'rb')

        ## Read Global Header
        glob_hdr_data = self.fd.read(NETOS_PCAP_GLOB_HDR_LEN)
        if self.glob_hdr.parse(glob_hdr_data) == False:
            return False

        return True

    def read_record(self, record : netos_pcap_record):
        return record.parse(self.fd, self.glob_hdr.endian)

if __name__ == "__main__":
    filename = sys.argv[1]
    count = 0
    pcap = netos_pcap_context()
    if not pcap.open_file(filename):
        print("failed to open file.. invalid pcap file format")
        sys.exit(1)

    while True:
        rec = netos_pcap_record()
        pkt_data = pcap.read_record(rec)
        if not pkt_data:
            print("end of pcap record. total records " + str(count))
            break

        count += 1

        rec.print()
        print(pkt_data.hex())

