#!/usr/bin/python3

import argparse
from scapy.all import *

def run_icmp6(ifname):
    sendp(Ether()/IPv6(dst="ff02::1")/ICMPv6EchoRequest(), iface=ifname)

def run_udp(ifname):
    sendp(Ether()/IPv6(dst="ff02::1")/UDP(dport=8000), iface=ifname)

def run_tcp(ifname):
    sendp(Ether()/IPv6(dst="ff02::1")/TCP(dport=80, flags="S"), iface=ifname)

def run_ipv6_tests(ifname):
    run_tcp(ifname)
    run_udp(ifname)
    run_icmp6(ifname)

def main():
    parser = argparse.ArgumentParser(description="Argument parser for netos tests")

    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface (e.g., dummy0)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of packets to send")

    args = parser.parse_args()

    run_ipv6_tests(args.interface)

if __name__ == "__main__":
    main()
