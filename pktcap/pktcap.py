#!/usr/bin/python3

import argparse

class cmdline_args:
    def __init__(self):
        self.ifname = ""
        self.pcap_file = ""

    def parse(self):
        parser = argparse.ArgumentParser(description='Packet Capture Tool')
        parser.add_argument('-i', '--interface', required=True, help='Interface to capture packets from')
        parser.add_argument('-w', '--pcap-file', required=True, help='Pcap file to write packets to')

        args = parser.parse_args()
        self.ifname     = args.interface
        self.pcap_file  = args.pcap_file

class pktcap:
    def __init__(self):
        self.args = cmdline_args()
        self.args.parse()

    def run(self):
        pass

if __name__ == "__main__":
    pc = pktcap()
    pc.run()
