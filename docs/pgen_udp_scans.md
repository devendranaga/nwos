# PGEN UDP SCANS

Purpose: The purpose of this document is to clearly understand networking and scanning techniques for good.
This is not intended to be used for malicious purposes. Doing this helps us understand the network better and how to protect
and prevent from attacks.

## Passive mode

command: udp passive_scan

In passive mode scanning, the pgen would listen on the raw socket waiting on the udp messages.
The udp frames are parsed and looked at the destination ip and port.

A format of the frames at L3 and L4 may look as follows:

```
ip_src, ip_dst, udp_src, udp_dst
..
```

A table must be created to hold these entries. List is good enough candidate for a display. It does not need to be performant.

The list must start with `ip_src` with a `ip_dst` with a list of `udp_port`s that it contains. This provides information that the `ip_dst` offers various services over udp.
This also means that the `ip_src` is in need of these services.

```c
struct udp_dst_info {
    uint32_t dst_ip;
    uint32_t n_dst_ports;
    uint16_t dst_ports[32 * 32];
    struct udp_dst_ports *next;
};

struct udp_info {
    uint32_t ip_src;
    struct udp_dst_info *dst_infos;
    uint32_t count; // number of times they communicated
};
```

The udp passive_scan command must also need to be listened to the incoming ARPs. This helps identifying the systems within the LAN.
The LAN network can then be figured from the bigger list above.

An ARP list would then contain the ip and mac address.

```c
struct arp_info {
    uint32_t ipaddr;
    uint8_t mac[6];
};
```

Once the ARP list is created. Each IP is then compared against the IP in the UDP scan list. If there is a match, then map it to either `ip_src` or `ip_dst`.


If its `ip_src` then list down what services it needs.
If its `ip_dst` then list down what services it provides.



The usefulness of this is it will help to misdirect `ip_src` to listen for messaages from a fake `ip_dst`. 
