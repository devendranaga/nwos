#ifndef NETOS_PROTOCOLS_ARP_H
#define NETOS_PROTOCOLS_ARP_H

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

#define NETOS_SET_MACADDR(__tgt_mac, __src_mac) do {\
    __tgt_mac[0] = __src_mac[0];\
    __tgt_mac[1] = __src_mac[1];\
    __tgt_mac[2] = __src_mac[2];\
    __tgt_mac[3] = __src_mac[3];\
    __tgt_mac[4] = __src_mac[4];\
    __tgt_mac[5] = __src_mac[5];\
} while (0)

#define NETOS_ARP_DEFAULTS(__arp_h, __sha, __spa, __tha, __tpa) do {\
    (__arp_h)->hwtype               = NETOS_ARP_HWTYPE_ETHER;\
    (__arp_h)->protocol_type        = NETOS_ARP_PROTOCOL_TYPE_IPV4;\
    (__arp_h)->hw_addr_len          = 6;\
    (__arp_h)->protocol_len         = 4;\
    NETOS_SET_MACADDR(((__arp_h)->sender_hwaddr), __sha);\
    (__arp_h)->sender_protocol_addr = __spa;\
    NETOS_SET_MACADDR(((__arp_h)->target_hwaddr), __tha);\
    (__arp_h)->target_protocol_addr = __tpa;\
} while (0)

#define NETOS_ARP_REQ_DEFAULTS(__arp_h, __sha, __spa, __tha, __tpa) do {\
    (__arp_h)->op = NETOS_ARP_OP_REQUEST;\
    NETOS_ARP_DEFAULTS(__arp_h, __sha, __spa, __tha, __tpa);\
} while (0)

typedef struct netos_arp_mib {
    uint64_t    in_arp;
    uint64_t    in_arp_invalid;
    uint64_t    in_arp_valid;
} netos_arp_mib_t;

typedef struct netos_arp_protocol {
    netos_arp_mib_t mib;
} netos_arp_protocol_t;

netos_status_t netos_arp_decode(netos_arp_hdr_t *arp_hdr, pkt_buffer_t *pkt_buf);

void netos_arp_print(netos_arp_hdr_t *arp_hdr);

netos_status_t netos_arp_rx_process(pkt_buffer_t *pkt_buf,
                                    netos_arp_protocol_t *arp_ctx);
#endif

