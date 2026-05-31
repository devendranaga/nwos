#ifndef NETOS_PROTOCOLS_ARP_H
#define NETOS_PROTOCOLS_ARP_H

#include <stdint.h>

#include "protocol_const.h"
#include "netos_status.h"
#include "pkt_buffer.h"

#define NETOS_ARP_HDR_LEN 28

typedef struct netos_arp_hdr {
    uint16_t    hwtype;
    uint16_t    protocol_type;
    uint8_t     hw_addr_len;
    uint8_t     protocol_len;
    uint16_t    op;
    uint8_t     sender_hwaddr[NETOS_MACADDR_LEN];
    uint32_t    sender_protocol_addr;
    uint8_t     target_hwaddr[NETOS_MACADDR_LEN];
    uint32_t    target_protocol_addr;
} netos_arp_hdr_t;

netos_status_t netos_arp_decode(netos_arp_hdr_t *arp_hdr, pkt_buffer_t *pkt_buf);

#endif

