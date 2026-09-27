#!/usr/bin/python3

from pkt_buffer import *

class netos_eth:
    def __init__(self):
        self.dst_mac = []
        self.src_mac = []
        self.ethertype = 0

    def parse(self, pkt_buf : netos_pkt_buffer):
        self.dst_mac = pkt_buf.get_mac_addr()
        self.src_mac = pkt_buf.get_mac_addr()
        self.ethertype = pkt_buf.get_2_bytes()

    def print(self):
        print("eth:")
        print("\t dst_mac: " + f"{self.dst_mac[0]:x}:{self.dst_mac[1]:x}:{self.dst_mac[2]:x}:"
                            + f"{self.dst_mac[3]:x}:{self.dst_mac[4]:x}:{self.dst_mac[5]:x}")
        print("\t src_mac: " + str(self.src_mac[0]) + ":" + str(self.src_mac[1]))
        print("\t ethertype: " + str(self.ethertype))

