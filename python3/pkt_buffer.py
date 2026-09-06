#!/usr/bin/python3

class netos_pkt_buffer:
    def __init__(self):
        self.buf = []
        self.offset = 0
        self.len = 0

    def get_2_bytes(self):
        val = (self.buf[self.offset] << 8) |
              (self.buf[self.offset + 1]);
        self.offset += 2;

        return val

