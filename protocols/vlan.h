#ifndef NETOS_PROTOCOLS_VLAN_H
#define NETOS_PROTOCOLS_VLAN_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

#include "netos_status.h"
#include "pkt_buffer.h"

#define NETOS_VLAN_HDR_LEN 4

typedef struct netos_vlan_hdr {
    uint16_t                vlan_id;
    uint8_t                 pcp;
    uint8_t                 dei;
    uint16_t                ethertype;
} netos_vlan_hdr_t;

netos_status_t netos_vlan_decode(netos_vlan_hdr_t *vlan_hdr,
                                 pkt_buffer_t *pkt_buf);

#if defined(__cplusplus)
}
#endif

#endif
