#ifndef IDS_SRC_PARSED_PKT_H
#define IDS_SRC_PARSED_PKT_H

#include <stdio.h>
#include <stdint.h>

#include "eth.h"
#include "vlan.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "udp.h"
#include "tcp.h"

namespace netos {

namespace ids {

struct parsed_pkt_types {
    uint32_t has_vlan   :1;
    uint32_t has_arp    :1;
    uint32_t has_ipv4   :1;
    uint32_t has_ipv6   :1;
    uint32_t has_udp    :1;
    uint32_t has_tcp    :1;
} __attribute__ ((__packed__));

struct parsed_pkt {
    char                *ingress_intf;
    parsed_pkt_types    pkt_types_present;
    eth_hdr             eh;
    vlan_hdr            vh;
    union {
        arp_hdr         ah;
    } l2;
    union {
        ipv4_hdr        ipv4_h;
    } l3;
    union {
        udp_hdr         udp_h;
    } l4;
};

}

}

#endif
