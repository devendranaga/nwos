#!/usr/bin/bash

# create dummy interfaces
sudo ip link add dummy0 type dummy
sudo ip link add dummy1 type dummy

# bring up the interfaces
sudo ip link set dummy0 up
sudo ip link set dummy1 up

sudo ./netos_netwd -f ../config/network.json
