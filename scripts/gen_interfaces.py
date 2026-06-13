#!/usr/bin/python3

import sys
import os

## Creates dummy interface and brings it up
def create_interface(ifname):
    cmd = "sudo ip link add " + ifname + " type dummy"
    os.system(cmd)

    cmd = "sudo ip link set " + ifname + " up"
    os.system(cmd)

## Delete the interface
def delete_interface(ifname):
    cmd = "sudo ip link del " + ifname
    os.system(cmd)

if len(sys.argv) != 4:
    print("<gen_interfaces> <create/delete> <ifname-pattern> <num interfaces>")
    exit(1)

ifname_str = sys.argv[2]
n_ifname = int(sys.argv[3])

print(n_ifname)
print(sys.argv[1] + " " + sys.argv[2])

for i in range(n_ifname):
    ifname = ifname_str + str(i)
    if sys.argv[1] == "create":
        create_interface(ifname)
    elif sys.argv[1] == "delete":
        delete_interface(ifname)
