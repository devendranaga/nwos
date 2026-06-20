#ifndef NETOS_PROTOCOLS_ICMP_H
#define NETOS_PROTOCOLS_ICMP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include "netos_status.h"
#include "pkt_buffer.h"

typedef struct {
    uint16_t    identifier;
    uint16_t    seq_no;
} netos_icmp_echo_t;

typedef struct {
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;
    uint16_t    start_off;

    union {
        netos_icmp_echo_t echo_req;
        netos_icmp_echo_t echo_reply;
    } u;
} netos_icmp_hdr_t;

netos_status_t netos_icmp_decode(netos_icmp_hdr_t *icmp_hdr, pkt_buffer_t *pkt_buf);

#if defined(__cplusplus)
}
#endif

#endif

