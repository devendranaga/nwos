#ifndef NETOS_PROTOCOLS_IPV4_H
#define NETOS_PROTOCOLS_IPV4_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdbool.h>
#include "protocols.h"

#define NETOS_IPV4_VERSION          4
#define NETOS_IPV4_HDR_LEN_DEFAULT  20
#define NETOS_IPV4_HDR_LEN_MAX      60
#define NETOS_IPV4_TTL_DEFAULT      64

/**
 * @brief - Defines IPv4 Flags.
 */
typedef struct __attribute__ ((__packed__)) {
    uint8_t     reserved            :1;
    uint8_t     dont_fragment       :1;
    uint8_t     more_fragment       :1;
    uint16_t    frag_off            :13;
} netos_ipv4_flags_t;

/**
 * @brief - Defines IPv4 header.
 */
typedef struct netos_ipv4_hdr {
    uint8_t             version         :4;
    uint8_t             header_len      :4;
    uint8_t             dscp            :6;
    uint8_t             ecn             :2;
    uint16_t            total_len;
    uint16_t            identification;
    bool                gen_checksum;
    netos_ipv4_flags_t  flags;
    uint8_t             ttl;
    uint8_t             protocol;
    uint16_t            hdr_chksum;
    uint32_t            src_ipaddr;
    uint32_t            dst_ipaddr;
} netos_ipv4_hdr_t;

/**
 * @brief - Set the IPv4 header defaults.
 *
 * @param [out] __ipv4_hdr - IPv4 header.
 * @param [in] __total_len - total length.
 * @param [in] __id - IPv4 id.
 * @param [in] __protocol - IPv4 protocol.
 * @param [in] __src_ipaddr - IPv4 src ip address.
 * @param [in] __dst_ipaddr - IPV4 dst ip address.
 */
#define NETOS_IPV4_DEFAULTS(__ipv4_hdr,\
                            __total_len,\
                            __id,\
                            __protocol,\
                            __src_ipaddr,\
                            __dst_ipaddr) do {\
    (__ipv4_hdr).version                = NETOS_IPV4_VERSION;\
    (__ipv4_hdr).header_len             = (NETOS_IPV4_HDR_LEN_DEFAULT / 4);\
    (__ipv4_hdr).dscp                   = 0;\
    (__ipv4_hdr).ecn                    = 0;\
    (__ipv4_hdr).total_len              = __total_len;\
    (__ipv4_hdr).identification         = __id;\
    (__ipv4_hdr).gen_checksum           = false;\
    (__ipv4_hdr).flags.reserved         = 0;\
    (__ipv4_hdr).flags.dont_fragment    = 1;\
    (__ipv4_hdr).flags.more_fragment    = 0;\
    (__ipv4_hdr).ttl                    = NETOS_IPV4_TTL_DEFAULT;\
    (__ipv4_hdr).protocol               = __protocol;\
    (__ipv4_hdr).hdr_chksum             = 0;\
    (__ipv4_hdr).src_ipaddr             = __src_ipaddr;\
    (__ipv4_hdr).dst_ipaddr             = __dst_ipaddr;\
} while (0)

/**
 * @brief - Decode IPv4 header.
 *
 * @param [inout] ipv4_hdr - IPv4 header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_ipv4_decode(netos_ipv4_hdr_t *ipv4_hdr, pkt_buffer_t *pkt_buf);

/**
 * @brief - Encode IPv4 header.
 *
 * @param [in] ipv4_hdr - IPv4 header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_ipv4_encode(netos_ipv4_hdr_t *ipv4_hdr, pkt_buffer_t *pkt_buf);

/**
 * @brief - Print IPv4 header.
 *
 * @param [in] ipv4_hdr - IPv4 header.
 */
void netos_ipv4_print(netos_ipv4_hdr_t *ipv4_hdr);

#if defined(__cplusplus)
}
#endif

#endif

