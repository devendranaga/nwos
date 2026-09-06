#!/usr/bin/python3

from pkt_buffer import *

class netos_pcap_glob_hdr:
    def __init__(self):
        self.magic = 0
        self.version_major = 0
        self.version_minor = 0
        self.thiszone = 0
        self.sigfigs = 0
        self.snaplen = 0
        self.network = 0

class netos_pcap_record:
    def __init__(self):
        self.ts_sec = 0
        self.ts_usec = 0
        self.incl_len = 0
        self.orig_len = 0
        self.buf = pkt_buffer()

class netos_pcap_context:
    def __init__(self):
        self.fd = -1
        self.offset = 0

    def open_file(self, filename):
        pass

    def read_record(self, record : netos_pcap_record):
        pass

