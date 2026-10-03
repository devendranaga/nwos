#!/usr/bin/python3

from pkt_buffer import *

class netos_eth:
    def __init__(self):
        self.dst_mac = []
        self.src_mac = []
        self.ethertype = 0

    def fill(self, pkt_buf : netos_pkt_buffer):
        pkt_buf.put_mac_addr(self.dst_mac)
        pkt_buf.put_mac_addr(self.src_mac)
        pkt_buf.put_2_bytes(self.ethertype)

    def parse(self, pkt_buf : netos_pkt_buffer):
        self.dst_mac = pkt_buf.get_mac_addr()
        self.src_mac = pkt_buf.get_mac_addr()
        self.ethertype = pkt_buf.get_2_bytes()

    def print(self):
        print("eth:")
        print("\t dst_mac: " + f"{self.dst_mac[0]:x}:{self.dst_mac[1]:x}:{self.dst_mac[2]:x}:"
                            + f"{self.dst_mac[3]:x}:{self.dst_mac[4]:x}:{self.dst_mac[5]:x}")
        print("\t src_mac: " + f"{self.src_mac[0]:x}:{self.src_mac[1]:x}:{self.src_mac[2]:x}:"
                            + f"{self.src_mac[3]:x}:{self.src_mac[4]:x}:{self.src_mac[5]:x}")
        print("\t ethertype: " + str(self.ethertype))

