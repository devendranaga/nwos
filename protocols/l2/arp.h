#ifndef PROTOCOLS_L2_ARP_H
#define PROTOCOLS_L2_ARP_H

#include <stdint.h>
#include <memory>

#include "ids_macro_defs.h"
#include "packet_buf.h"
#include "error_codes.h"

#define NETOS_ARP_HWTYPE                1
#define NETOS_ARP_HW_ADDR_LEN           6
#define NETOS_ARP_PROTOCOL_ADDR_LEN     4

#define NETOS_ARP_OP_ARP_REQUEST        1
#define NETOS_ARP_OP_ARP_REPLY          2
#define NETOS_ARP_OP_RARP_REQ           3
#define NETOS_ARP_OP_RARP_REPLY         4
#define NETOS_ARP_OP_DRARP_REQ          5
#define NETOS_ARP_OP_DRARP_REPLY        6
#define NETOS_ARP_OP_DRARP_ERROR        7
#define NETOS_ARP_OP_INARP_REQ          8
#define NETOS_ARP_OP_INARP_REPLY        9

namespace netos {

struct arp_hdr {
    uint16_t                hw_type;
    uint16_t                protocol_type;
    uint8_t                 ha_len;
    uint8_t                 proto_len;
    uint16_t                op;
    uint8_t                 sender_hwaddr[NETOS_IDS_MACADDR_LEN];
    uint32_t                sender_protocol_addr;
    uint8_t                 target_hwaddr[NETOS_IDS_MACADDR_LEN];
    uint32_t                target_protocol_addr;

    explicit arp_hdr() { }
    ~arp_hdr() { }

    netos_status serialize(std::shared_ptr<packet_buf> &buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &buf);
};

}

#endif

