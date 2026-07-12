#ifndef PROTOCOLS_ICMP6_HDR_H
#define PROTOCOLS_ICMP6_HDR_H

#if defined(__cplusplus)
extern "C" {
#endif

#define NETOS_ICMP6_TYPE_ECHO_REQ   128
#define NETOS_ICMP6_TYPE_ECHO_REPLY 129
#define NETOS_ICMP6_CODE_ECHO_REQ   0
#define NETOS_ICMP6_CODE_ECHO_REPLY 0

/**
 * @brief - Defines ICMP6 echo request.
 */
typedef struct {
    uint16_t    identifier;
    uint16_t    seq_no;
    uint8_t     *data;
    uint16_t    data_len;
} netos_icmp6_echo_req_t;

/**
 * @brief - Defines ICMP6 echo reply.
 */
typedef struct {
    uint16_t    identifier;
    uint16_t    seq_no;
    uint8_t     *data;
    uint16_t    data_len;
} netos_icmp6_echo_reply_t;

/**
 * @brief - Defines ICMP6 header.
 */
typedef struct {
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;

    union {
        netos_icmp6_echo_req_t      echo_req;
        netos_icmp6_echo_reply_t    echo_reply;
    } u;
} netos_icmp6_hdr_t;

/**
 * @brief - Decode ICMP6 header.
 *
 * @param [inout] - ICMP6 header.
 * @param [inout] - pkt buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_icmp6_decode(netos_icmp6_hdr_t *icmp6_hdr,
                                  pkt_buffer_t *pkt_buf);

#if defined(__cplusplus)
}
#endif

#endif

