#ifndef IDS_SRC_PARSED_PKT_H
#define IDS_SRC_PARSED_PKT_H

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <memory>

#include "packet_buf.h"
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
    std::shared_ptr<packet_buf> pkt_buf;
    std::string                 ifname;
    parsed_pkt_types            pkt_types_present;
    eth_hdr                     eh;
    vlan_hdr                    vh;
    arp_hdr                     ah;
    ipv4_hdr                    ipv4_h;
    udp_hdr                     udp_h;

    explicit parsed_pkt() {}
    ~parsed_pkt() {}
};

}

}

#endif
