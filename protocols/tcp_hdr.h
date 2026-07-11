#ifndef NETOS_PROTOCOLS_TCP_H
#define NETOS_PROTOCOLS_TCP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

// TCP protocol macro defines
#define NETOS_TCP_HDR_LEN_DEFAULT 20

/**
 * @brief - TCP flags.
 */
typedef struct {
    uint8_t reserved:3;
    uint8_t ecn     :1;
    uint8_t cwr     :1;
    uint8_t ece     :1;
    uint8_t urg     :1;
    uint8_t ack     :1;
    uint8_t psh     :1;
    uint8_t rst     :1;
    uint8_t syn     :1;
    uint8_t fin     :1;
} netos_tcp_flags_t;

/**
 * @brief - TCP header.
 */
typedef struct {
    uint16_t            src_port;
    uint16_t            dst_port;
    uint32_t            seq_no;
    uint32_t            ack_no;
    uint8_t             hdr_len;
    netos_tcp_flags_t   flags;
    uint16_t            window;
    uint16_t            chksum;
    uint16_t            urg;
} netos_tcp_hdr_t;

/**
 * @brief - Decode TCP header.
 *
 * @param [inout] tcp_hdr - TCP header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_tcp_decode(netos_tcp_hdr_t *tcp_hdr, pkt_buffer_t *pkt_buf);

void netos_tcp_print(netos_tcp_hdr_t *tcp_hdr);

#if defined(__cplusplus)
}
#endif

#endif
