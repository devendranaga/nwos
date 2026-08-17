from scapy.all import Ether, IP, ICMP, sendp

# Define target parameters (modify interface and MAC/IP addresses as needed)
INTERFACE = "dummy0"
DST_MAC = "ff:ff:ff:ff:ff:ff"  # Broadcast or specific next-hop MAC
DST_IP = "192.168.1.10"

# Comprehensive dictionary mapping ICMP Types to their valid Codes
# Based on official IANA assignments
icmp_map = {
    0: [0],          # Echo Reply
    3: list(range(16)) + [13, 14, 15],  # Destination Unreachable (Codes 0-15)
    4: [0],          # Source Quench (Deprecated)
    5: [0, 1, 2, 3], # Redirect
    8: [0],          # Echo Request
    9: [0],          # Router Advertisement
    10: [0],         # Router Selection
    11: [0, 1],      # Time Exceeded
    12: [0, 1, 2],   # Parameter Problem
    13: [0],         # Timestamp
    14: [0],         # Timestamp Reply
    15: [0],         # Information Request
    16: [0],         # Information Reply
    17: [0],         # Address Mask Request
    18: [0]          # Address Mask Reply
}

print(f"Starting transmission of all ICMP types/codes on interface {INTERFACE}...")

packet_count = 0

# Loop through types and codes, building and sending one frame per combination
for icmp_type, codes in icmp_map.items():
    for icmp_code in codes:
        # Construct Layer 2 (Ethernet) + Layer 3 (IP) + ICMP frame
        frame = Ether(dst=DST_MAC) / IP(dst=DST_IP) / ICMP(type=icmp_type, code=icmp_code)

        # Send via sendp at layer 2 on the chosen interface
        sendp(frame, iface=INTERFACE, verbose=False)

        print(f"Sent -> Type: {icmp_type}, Code: {icmp_code}")
        packet_count += 1

print(f"Finished! Successfully transmitted {packet_count} unique ICMP frames.")


