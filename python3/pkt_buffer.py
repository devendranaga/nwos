#!/usr/bin/python3

class netos_pkt_buffer:
    def __init__(self):
        self.buf = []
        self.offset = 0
        self.len = 0

    def get_2_bytes(self):
        val = (self.buf[self.offset] << 8) |\
              (self.buf[self.offset + 1]);
        self.offset += 2;

        return val

    def get_4_bytes(self):

        val = (self.buf[self.offset] << 24) |\
              (self.buf[self.offset + 1] << 16) |\
              (self.buf[self.offset + 2] << 8) |\
              (self.buf[self.offset + 3]);
        self.offset += 4;

        return val;

    def get_mac_addr(self):
        val = self.buf[:self.offset + 6]
        self.offset += 6

        return val

    def set_rx_buf(self, rx_buf):
        self.buf = bytearray(rx_buf)
        self.len = len(self.buf)


