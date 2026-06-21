#ifndef NETOS_PROTOCOLS_ICMP_H
#define NETOS_PROTOCOLS_ICMP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include "netos_status.h"
#include "pkt_buffer.h"

#define NETOS_ICMP_TYPE_ECHO_REQ        8
#define NETOS_ICMP_TYPE_ECHO_REPLY      0
#define NETOS_ICMP_TYPE_TIMESTAMP_REQ   13
#define NETOS_ICMP_TYPE_TIMESTAMP_REPLY 14
#define NETOS_ICMP_CODE_ECHO_REQ        0
#define NETOS_ICMP_CODE_ECHO_REPLY      0
#define NETOS_ICMP_CODE_TIMESTAMP_REQ   0
#define NETOS_ICMP_CODE_TIMESTAMP_REPLY 0

#define NETOS_ICMP_HDR_LEN              4
#define NETOS_ICMP_ECHO_REQ_LEN         4
#define NETOS_ICMP_ECHO_REPLY_LEN       4
#define NETOS_ICMP_TIMESTAMP_LEN        16

typedef struct {
    uint16_t    identifier;
    uint16_t    seq_no;
    uint16_t    data_len;
} netos_icmp_echo_t;

typedef struct {
    uint16_t    identifier;
    uint16_t    seq_no;
    uint32_t    originate_ts;
    uint32_t    receive_ts;
    uint32_t    transmit_ts;
} netos_icmp_timestamp_t;

typedef struct {
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;

    union {
        netos_icmp_echo_t       echo_req;
        netos_icmp_echo_t       echo_reply;
        netos_icmp_timestamp_t  ts_req;
        netos_icmp_timestamp_t  ts_reply;
    } u;
} netos_icmp_hdr_t;

netos_status_t netos_icmp_decode(netos_icmp_hdr_t *icmp_hdr, pkt_buffer_t *pkt_buf);

#if defined(__cplusplus)
}
#endif

#endif

