#ifndef NETOS_PROTOCOLS_ETH_H
#define NETOS_PROTOCOLS_ETH_H

#include <string.h>
#include "netos_status.h"
#include "protocol_const.h"
#include "pkt_buffer.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define NETOS_ETH_HDR_LEN 14

#define NETOS_IS_MULTICAST(__mac) !!(__mac[0] & 0x01)

/**
 * @brief - Defines ethernet header.
 */
typedef struct netos_eth_hdr {
    uint8_t     dst[NETOS_MACADDR_LEN];
    uint8_t     src[NETOS_MACADDR_LEN];
    uint16_t    ethertype;
} netos_eth_hdr_t;

/**
 * @brief - prepare an ethernet header with the below defaults.
 *
 * @param [out] __eh        - ethernet header.
 * @param [in] __dst        - destination mac.
 * @param [in] __src        - source mac.
 * @param [in] __ethertype  - ethertype.
 */
#define NETOS_ETH_DEFAULTS(__eh, __dst, __src, __ethertype) do {\
    memcpy((__eh).dst, (__dst), NETOS_MACADDR_LEN);\
    memcpy((__eh).src, (__src), NETOS_MACADDR_LEN);\
    __eh.ethertype = __ethertype;\
} while (0)

/**
 * @brief - Decode an ethernet header.
 *
 * @param [out] eh - ethernet header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_eth_decode(netos_eth_hdr_t *eh,
                                pkt_buffer_t *pkt_buf);

netos_status_t netos_eth_encode(netos_eth_hdr_t *eh,
                                pkt_buffer_t *pkt_buf);

void netos_eth_print(netos_eth_hdr_t *eh);

#if defined(__cplusplus)
}
#endif

#endif

