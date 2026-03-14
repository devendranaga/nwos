#ifndef PROTOCOLS_L2_ARP_HDR_H
#define PROTOCOLS_L2_ARP_HDR_H

#include <stdint.h>
#include <iostream>
#include <memory>

#include "ethertypes.h"
#include "netos_macros.h"
#include "error_codes.h"
#include "packet_buf.h"

using namespace netos::lib;

/* ARP header constants. */
#define ARP_HW_TYPE_ETHERNET            1
#define ARP_HA_LEN                      6
#define ARP_PROTOCOL_LEN                4

#define NETOS_ARP_HWTYPE                1
#define NETOS_ARP_HW_ADDR_LEN           6
#define NETOS_ARP_PROTOCOL_ADDR_LEN     4

/* ARP op valid values. */
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

/**
 * @brief - Defines ARP header.
 */
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

    void arp_reply_defaults(uint8_t *my_macaddr,
                            uint8_t *target_mac,
                            uint32_t my_protocol_addr,
                            uint32_t target_protocol_addr)
    {
        this->hw_type               = ARP_HW_TYPE_ETHERNET;
        this->protocol_type         = NETOS_ETHERTYPE_IPV4;
        this->ha_len                = ARP_HA_LEN;
        this->proto_len             = ARP_PROTOCOL_LEN;
        memcpy(this->sender_hwaddr, my_macaddr, NETOS_MACADDR_LEN);
        this->sender_protocol_addr  = my_protocol_addr;
        memcpy(this->target_hwaddr, target_mac, NETOS_MACADDR_LEN);
        this->target_protocol_addr  = target_protocol_addr;
        this->op                    = NETOS_ARP_OP_ARP_REPLY;
    }

    void arp_request_defaults(uint8_t *my_macaddr,
                              uint8_t *target_mac,
                              uint32_t my_protocol_addr,
                              uint32_t target_protocol_addr)
    {
        this->hw_type               = ARP_HW_TYPE_ETHERNET;
        this->protocol_type         = NETOS_ETHERTYPE_IPV4;
        this->ha_len                = ARP_HA_LEN;
        this->proto_len             = ARP_PROTOCOL_LEN;
        memcpy(this->sender_hwaddr, my_macaddr, NETOS_MACADDR_LEN);
        this->sender_protocol_addr  = my_protocol_addr;
        memcpy(this->target_hwaddr, target_mac, NETOS_MACADDR_LEN);
        this->target_protocol_addr  = target_protocol_addr;
        this->op                    = NETOS_ARP_OP_ARP_REQUEST;
    }

    netos_status serialize(packet_buf *buf);
    netos_status deserialize(packet_buf *buf);
    void print();
};

}

#endif

