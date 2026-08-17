from scapy.all import Ether, IP, UDP, ICMP, sendp

# Network parameters
INTERFACE = "dummy0"
SRC_MAC = "00:11:22:33:44:55"  # Router/Responder MAC
DST_MAC = "66:55:44:33:22:11"  # Original sender MAC
ROUTER_IP = "192.168.1.1"      # IP of the router/host sending the error
ORIGINAL_SENDER = "192.168.1.50" # Who originally sent the bad packet
CLOSED_TARGET = "192.168.1.100"  # Intended destination
CLOSED_PORT = 33434            # The unreachable port (e.g., traceroute or closed service)

# 1. Craft the original inner IP + UDP packet that "triggered" the failure
inner_packet = IP(src=ORIGINAL_SENDER, dst=CLOSED_TARGET) / UDP(sport=54321, dport=CLOSED_PORT) / (b"A" * 8)

# 2. Craft the outer ICMP Destination Unreachable (Type 3, Code 3) encapsulating the inner packet header
icmp_error = (
    Ether(src=SRC_MAC, dst=DST_MAC) /
    IP(src=ROUTER_IP, dst=ORIGINAL_SENDER) /
    ICMP(type=3, code=3) /
    inner_packet
)

# 3. Transmit the legitimate structured frame over the interface
sendp(icmp_error, iface=INTERFACE)
print("Sent legitimate and fully-nested ICMP Destination Port Unreachable frame.")


