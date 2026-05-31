#ifndef NETOS_PROTOCOLS_UDP_H
#define NETOS_PROTOCOLS_UDP_H

#include <stdint.h>

#include "pkt_buffer.h"
#include "netos_status.h"

#define NETOS_UDP_HDR_LEN 8

typedef struct netos_udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} netos_udp_hdr_t;

netos_status_t netos_udp_decode(netos_udp_hdr_t *udp_hdr, pkt_buffer_t *pkt_buf);

#endif
