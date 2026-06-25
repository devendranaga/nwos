#ifndef NETOS_PROTOCOLS_VLAN_H
#define NETOS_PROTOCOLS_VLAN_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

#include "netos_status.h"
#include "pkt_buffer.h"

#define NETOS_VLAN_HDR_LEN      4

/**
 * @brief - Defines VLAN header.
 */
typedef struct netos_vlan_hdr {
    uint16_t                vlan_ethertype;
    uint16_t                vlan_id;
    uint8_t                 pcp;
    uint8_t                 dei;
    uint16_t                ethertype;
} netos_vlan_hdr_t;

/**
 * @brief - Set VLAN defaults.
 *
 * @param [out] __vh        - VLAN header.
 * @param [in] __id         - VLAN id.
 * @param [in] __priority   - VLAN priority.
 * @param [in] __dei        - VLAN dei.
 * @param [in] __ethertype  - ethertype.
 */
#define NETOS_VLAN_DEFAULTS(__vh, __id, __priority, __dei, __ethertype) do {\
    (__vh).vlan_id      = __id;\
    (__vh).pcp          = __priority;\
    (__vh).dei          = __dei;\
    (__vh).ethertype    = __ethertype;\
} while (0)

/**
 * @brief - Decode VLAN header. Works for 0x8100, 0x9100 and 0x88A8.
 *
 * @param [out] vlan_hdr - VLAN header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_vlan_decode(netos_vlan_hdr_t *vlan_hdr,
                                 pkt_buffer_t *pkt_buf);

netos_status_t netos_vlan_encode(const netos_vlan_hdr_t *vlan_hdr,
                                 pkt_buffer_t *pkt_buf);

void netos_vlan_print(netos_vlan_hdr_t *vlan_hdr);

#if defined(__cplusplus)
}
#endif

#endif
