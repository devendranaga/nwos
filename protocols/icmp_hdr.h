#ifndef NETOS_PROTOCOLS_ICMP_H
#define NETOS_PROTOCOLS_ICMP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include "netos_status.h"
#include "pkt_buffer.h"

// List of ICMP types
#define NETOS_ICMP_TYPE_DEST_UNREACH    3
#define NETOS_ICMP_TYPE_ECHO_REQ        8
#define NETOS_ICMP_TYPE_ECHO_REPLY      0
#define NETOS_ICMP_TYPE_TIMESTAMP_REQ   13
#define NETOS_ICMP_TYPE_TIMESTAMP_REPLY 14

// List of ICMP codes
#define NETOS_ICMP_CODE_NW_UNREACH      0
#define NETOS_ICMP_CODE_HOST_UNREACH    1
#define NETOS_ICMP_CODE_PROT_UNREACH    2
#define NETOS_ICMP_CODE_ECHO_REQ        0
#define NETOS_ICMP_CODE_ECHO_REPLY      0
#define NETOS_ICMP_CODE_TIMESTAMP_REQ   0
#define NETOS_ICMP_CODE_TIMESTAMP_REPLY 0

// ICMP Macro defines
#define NETOS_ICMP_HDR_LEN              4
#define NETOS_ICMP_ECHO_REQ_LEN         4
#define NETOS_ICMP_ECHO_REPLY_LEN       4
#define NETOS_ICMP_TIMESTAMP_LEN        16
#define NETOS_ICMP_DEST_UNREACH_LEN     4

#define NETOS_ICMP_IS_ECHO_REQ(__icmp) (((__icmp)->type == NETOS_ICMP_TYPE_ECHO_REQ) &&\
                                        ((__icmp)->code == NETOS_ICMP_CODE_ECHO_REQ))

/**
 * @brief - ICMP echo.
 */
typedef struct {
    uint16_t    identifier;
    uint16_t    seq_no;
    uint16_t    data_len;
    uint8_t     *data;
} netos_icmp_echo_t;

typedef struct {
    uint32_t unused;
    uint16_t data_len;
    uint8_t  *data;
} netos_dest_unreachable_t;

/**
 * @brief - ICMP timestamp.
 */
typedef struct {
    uint16_t    identifier;
    uint16_t    seq_no;
    uint32_t    originate_ts;
    uint32_t    receive_ts;
    uint32_t    transmit_ts;
} netos_icmp_timestamp_t;

/**
 * @brief - Defines ICMP protocol.
 */
typedef struct {
    bool        gen_checksum;
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;

    union {
        netos_dest_unreachable_t    dest_unreach;
        netos_icmp_echo_t           echo_req;
        netos_icmp_echo_t           echo_reply;
        netos_icmp_timestamp_t      ts_req;
        netos_icmp_timestamp_t      ts_reply;
    } u;
} netos_icmp_hdr_t;

/**
 * @brief - helper to set icmp header to echo request defaults.
 *
 * @param [in] __icmp_hdr - ICMP header.
 * @param [in] __id - ICMP id.
 * @param [in] __seq_no - ICMP seq no.
 */
#define NETOS_ICMP_ECHO_REQ_DEFAULTS(__icmp_hdr, __id, __seq_no) do {\
    (__icmp_hdr).gen_checksum           = false;\
    (__icmp_hdr).type                   = NETOS_ICMP_TYPE_ECHO_REQ;\
    (__icmp_hdr).code                   = NETOS_ICMP_CODE_ECHO_REQ;\
    (__icmp_hdr).checksum               = 0;\
    (__icmp_hdr).u.echo_req.identifier  = __id;\
    (__icmp_hdr).u.echo_req.seq_no      = __seq_no;\
} while (0)

/**
 * @brief - helper to set the icmp echo reply to defaults.
 *
 * @param [in] __icmp_hdr - ICMP header.
 * @param [in] __id - ICMP id.
 * @param [in] __seq_no - ICMP seq no.
 */
#define NETOS_ICMP_ECHO_REPLY_DEFAULTS(__icmp_hdr, __id, __seq_no) do {\
    (__icmp_hdr).gen_checksum               = false;\
    (__icmp_hdr).type                       = NETOS_ICMP_TYPE_ECHO_REPLY;\
    (__icmp_hdr).code                       = NETOS_ICMP_CODE_ECHO_REPLY;\
    (__icmp_hdr).checksum                   = 0;\
    (__icmp_hdr).u.echo_reply.identifier    = __id;\
    (__icmp_hdr).u.echo_reply.seq_no        = __seq_no;\
} while (0)

/**
 * @brief - Decode ICMP header.
 *
 * @param [inout] icmp_hdr - ICMP header.
 * @param [inout] pkt - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_icmp_decode(netos_icmp_hdr_t *icmp_hdr, pkt_buffer_t *pkt_buf);

/**
 * @brief - Encode ICMP header.
 *
 * @param [in] icmp_hdr - ICMP header.
 * @param [inout] pkt - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_icmp_encode(netos_icmp_hdr_t *icmp_hdr, pkt_buffer_t *pkt_buf);

#if defined(__cplusplus)
}
#endif

#endif

