#!/usr/bin/env python3
from scapy.all import wrpcap
from scapy.layers.inet6 import (
    IPv6, 
    IPv6ExtHdrHopByHop, 
    IPv6ExtHdrDestOpt, 
    RouterAlert, 
    PadN,
    HBHOptUnknown,
    ICMPv6EchoRequest
)

def generate_ipv6_options_pcap(filename="ipv6_options.pcap"):
    print(f"[*] Generating IPv6 packets with extension options...")
    
    packets = []

    # -------------------------------------------------------------------------
    # Packet 1: Hop-by-Hop Options Header using built-in classes
    # Includes standard Router Alert and automatic padding alignment
    # -------------------------------------------------------------------------
    pkt1 = (
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        IPv6ExtHdrHopByHop(options=[
            RouterAlert(value=0),  # Standard MLD/RS Router Alert
            PadN(optlen=2)         # Ensures proper 8-octet alignment padding
        ]) /
        ICMPv6EchoRequest(data="Ping with HBH Option")
    )
    packets.append(pkt1)

    # Packet 2: Destination Options Header using custom/generic TLVs
    pkt2 = (
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        IPv6ExtHdrDestOpt(options=[
            # Change 'value' to 'optdata'
            HBHOptUnknown(otype=0x1E, optlen=4, optdata=b"\xaa\xbb\xcc\xdd"),
            PadN(optlen=2)
        ]) /
        ICMPv6EchoRequest(data="Ping with Dest Option")
    )
    packets.append(pkt2)

    # Packet 3: Chained Extension Headers
    pkt3 = (
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        IPv6ExtHdrHopByHop(options=[RouterAlert(value=0)]) /
        # Change 'value' to 'optdata'
        IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=0x1E, optlen=2, optdata=b"\x11\x22")]) /
        ICMPv6EchoRequest(data="Chained Headers")
    )
    packets.append(pkt3)

    # Write all crafted packets directly to a PCAP file
    wrpcap(filename, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to '{filename}'.")

if __name__ == "__main__":
    generate_ipv6_options_pcap()


