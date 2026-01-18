#ifndef PROTOCOLS_L2_ARP_HDR_H
#define PROTOCOLS_L2_ARP_HDR_H

#include <stdint.h>
#include <iostream>
#include <memory>

#include "ethertypes.h"
#include "ids_macro_defs.h"
#include "error_codes.h"
#include "packet_buf.h"

using namespace netos::lib;

#define ARP_HW_TYPE_ETHERNET 1
#define ARP_HA_LEN 6
#define ARP_PROTOCOL_LEN 4

// ARP operations
#define ARP_OP_ARP_REQUEST  1
#define ARP_OP_ARP_REPLY    2

namespace netos {

struct arp_hdr {
    uint16_t                hw_type;
    uint16_t                protocol_type;
    uint8_t                 ha_len;
    uint8_t                 proto_len;
    uint16_t                op;
    uint8_t                 sender_hwaddr[NETOS_MACADDR_LEN];
    uint32_t                sender_protocol_addr;
    uint8_t                 target_hwaddr[NETOS_MACADDR_LEN];
    uint32_t                target_protocol_addr;

    explicit arp_hdr() { }
    ~arp_hdr() { }

    netos_status serialize(std::shared_ptr<packet_buf> &buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &buf);
    void print();
};

}

#endif

