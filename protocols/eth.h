#ifndef NETOS_PROTOCOLS_ETH_H
#define NETOS_PROTOCOLS_ETH_H

#include "netos_status.h"
#include "protocol_const.h"
#include "pkt_buffer.h"

#define NETOS_ETH_HDR_LEN 14

#define NETOS_IS_MULTICAST(__mac) !!(mac[0] && 0x01)

typedef struct netos_eth_hdr {
    uint8_t     dst[NETOS_MACADDR_LEN];
    uint8_t     src[NETOS_MACADDR_LEN];
    uint16_t    ethertype;
} netos_eth_hdr_t;

netos_status_t netos_eth_decode(netos_eth_hdr_t *eh,
                                pkt_buffer_t *pkt_buf);

void netos_eth_print(netos_eth_hdr_t *eh);

#endif

