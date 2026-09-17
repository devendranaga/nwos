#ifndef PROTOCOLS_ICMP6_HDR_H
#define PROTOCOLS_ICMP6_HDR_H

#include "protocol_const.h"
#include "ipv6_hdr.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define NETOS_ICMP6_HDR_LEN_DEFAULT             4
#define NETOS_ICMP6_TYPE_ECHO_REQ               128
#define NETOS_ICMP6_TYPE_ECHO_REPLY             129
#define NETOS_ICMP6_TYPE_NS                     135
#define NETOS_ICMP6_TYPE_NA                     136
#define NETOS_ICMP6_CODE_ECHO_REQ               0
#define NETOS_ICMP6_CODE_ECHO_REPLY             0
#define NETOS_ICMP6_CODE_NS                     0
#define NETOS_ICMP6_CODE_NA                     0

#define NETOS_ICMP6_NS_OPT_SLL                  1
#define NETOS_ICMP6_NS_OPT_SLL_LEN              8

#define NETOS_ICMP6_ECHO_LEN                    4
#define NETOS_ICMP6_NS_LEN                      20 // no options
#define NETOS_ICMP6_NA_LEN                      20

#define NETOS_ICMP6_IS_ECHO_REQ(__icmp6_hdr) ((__icmp6_hdr)->type == NETOS_ICMP6_TYPE_ECHO_REQ)

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

typedef struct {
    uint8_t sll_addr[NETOS_MACADDR_LEN];
} netos_icmp6_ns_opt_sll_addr_t;

typedef struct {
    uint32_t    : 32;
    uint8_t     target_addr[NETOS_IPV6_ADDR_LEN];
    union {
        netos_icmp6_ns_opt_sll_addr_t sll_addr;
    } u;
} netos_icmp6_ns_t;

typedef struct {
    uint32_t    flags;
    uint8_t     target_addr[NETOS_IPV6_ADDR_LEN];
} netos_icmp6_na_t;

#define NETOS_ICMP6_ECHO_REPLY_DEFAULTS(__icmp6_hdr, __id, __seq_no) do {\
    (__icmp6_hdr).type                      = NETOS_ICMP6_TYPE_ECHO_REPLY;\
    (__icmp6_hdr).code                      = NETOS_ICMP6_CODE_ECHO_REPLY;\
    (__icmp6_hdr).checksum                  = 0;\
    (__icmp6_hdr).u.echo_reply.identifier   = __id;\
    (__icmp6_hdr).u.echo_reply.seq_no       = __seq_no;\
    (__icmp6_hdr).u.echo_reply.data         = NULL;\
    (__icmp6_hdr).u.echo_reply.data_len     = 0;\
} while (0)

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
        netos_icmp6_ns_t            ns;
        netos_icmp6_na_t            na;
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

