#!/usr/bin/python3

from enum import Enum

class netos_endian(Enum):
    Big     = 1
    Little  = 2

class netos_pkt_buffer:
    def __init__(self):
        self.buf    = []
        self.offset = 0
        self.len    = 0

    def get_2_bytes(self):
        val = (self.buf[self.offset] << 8) |\
              (self.buf[self.offset + 1])
        self.offset += 2

        return val

    def get_2_bytes_le(self):
        val = (self.buf[self.offset]) |\
              (self.buf[self.offset + 1] << 8)
        self.offset += 2

        return val

    def get_2_bytes_endian(self, endian : netos_endian):
        if endian == netos_endian.Big:
            return self.get_2_bytes()
        else:
            return self.get_2_bytes_le()

    def put_2_bytes_be(self, val):
        self.buf.append((val & 0xFF00) >> 8)
        self.buf.append(val & 0x00FF)
        self.offset += 2

    def put_2_bytes_le(self, val):
        self.buf.append(val & 0x00FF)
        self.buf.append((val & 0xFF00) >> 8)
        self.offset += 2

    def put_2_bytes_endian(self, val, endian : netos_endian):
        if endian == netos_endian.Big:
            self.put_2_bytes_be()
        else:
            self.put_2_bytes_le()

    def get_4_bytes(self):

        val = (self.buf[self.offset] << 24) |\
              (self.buf[self.offset + 1] << 16) |\
              (self.buf[self.offset + 2] << 8) |\
              (self.buf[self.offset + 3])
        self.offset += 4

        return val;

    def get_4_bytes_le(self):

        val = (self.buf[self.offset]) |\
              (self.buf[self.offset + 1] << 8) |\
              (self.buf[self.offset + 2] << 16) |\
              (self.buf[self.offset + 3] << 24)
        self.offset += 4

        return val;

    def get_4_bytes_endian(self, endian : netos_endian):
        if endian == netos_endian.Big:
            return self.get_4_bytes()
        else:
            return self.get_4_bytes_le()

    def get_mac_addr(self):
        val = self.buf[:self.offset + 6]
        self.offset += 6

        return val

    def put_mac_addr(self, mac):
        for val in mac:
            self.buf.append(val)
        self.offset += 6;

    def set_rx_buf(self, rx_buf):
        self.buf = bytearray(rx_buf)
        self.len = len(self.buf)

    def get_bytes(self):
        return bytes(self.buf)


