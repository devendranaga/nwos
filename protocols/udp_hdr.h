#ifndef NETOS_PROTOCOLS_UDP_H
#define NETOS_PROTOCOLS_UDP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

#include "pkt_buffer.h"
#include "netos_status.h"

#define NETOS_UDP_HDR_LEN 8

typedef struct netos_udp_hdr {
    uint16_t    src_port;
    uint16_t    dst_port;
    uint16_t    length;
    uint16_t    checksum;
    bool        gen_checksum;
} netos_udp_hdr_t;

#define NETOS_UDP_DEFAULTS(__udp_hdr, __src_port, __dst_port, __length, __checksum) do {\
    (__udp_hdr).src_port    = __src_port;\
    (__udp_hdr).dst_port    = __dst_port;\
    (__udp_hdr).length      = __length;\
    (__udp_hdr).checksum    = __checksum;\
} while (0)

/**
 * @brief - Decode UDP header.
 *
 * @param [inout] udp_hdr - UDP header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_udp_decode(netos_udp_hdr_t *udp_hdr, pkt_buffer_t *pkt_buf);

netos_status_t netos_udp_encode(netos_udp_hdr_t *udp_hdr,
                                pkt_buffer_t *pkt_buf);

#if defined(__cplusplus)
}
#endif

#endif
