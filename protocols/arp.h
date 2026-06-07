#ifndef NETOS_PROTOCOLS_ARP_H
#define NETOS_PROTOCOLS_ARP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

#include "protocol_const.h"
#include "netos_status.h"
#include "pkt_buffer.h"
#include "arp_hdr.h"
#include "packet_parser.h"
#include "hash_tables.h"

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

typedef struct netos_arp_entry {
    uint8_t mac[NETOS_MACADDR_LEN];
    uint32_t ipaddr;
} netos_arp_entry_t;

typedef struct netos_arp_protocol {
    netos_arp_mib_t mib;
    netos_hash_table_t *arp_cache;
} netos_arp_protocol_t;

netos_status_t netos_arp_rx_process(pkt_buffer_t *pkt_buf,
                                    netos_packet_parser_t *pkt_parser,
                                    netos_arp_protocol_t *arp_ctx);

#if defined(__cplusplus)
}
#endif

#endif

