#ifndef NETOS_PROTOCOLS_ARP_HDR_H
#define NETOS_PROTOCOLS_ARP_HDR_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

#include "protocol_const.h"
#include "netos_status.h"
#include "pkt_buffer.h"

#define NETOS_ARP_HDR_LEN 28
#define NETOS_ARP_HWTYPE_ETHER 1
#define NETOS_ARP_PROTOCOL_TYPE_IPV4 0x0800

#define NETOS_ARP_OP_REQUEST 1
#define NETOS_ARP_OP_REPLY 2

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

netos_status_t netos_arp_encode(netos_arp_hdr_t *arp_hdr, pkt_buffer_t *pkt_buf);

void netos_arp_print(netos_arp_hdr_t *arp_hdr);

#if defined(__cplusplus)
}
#endif

#endif

