#ifndef NETOS_SWITCHING_VLAN_CONV_H
#define NETOS_SWITCHING_VLAN_CONV_H

#include <stdint.h>
#include "raw_socket.h"

typedef enum {
    NETOS_VLAN_INTF_CHECK = 1, // just check the ingress vlan and simply egress and translate if present
    NETOS_VLAN_INTF_STRICT_INGRESS_MATCH, // drop if the ingress vlan is not matched
} netos_vlan_intf_mode_t;

typedef struct netos_vlan_lookup {
    uint16_t ingress_vlan;
    uint16_t egress_vlan;

    struct netos_vlan_lookup *next;
} netos_vlan_lookup_t;

typedef struct netos_vlan_info {
    netos_raw_socket_ctx_t  *raw; // interface
    netos_vlan_intf_mode_t  intf_mode;
    netos_vlan_lookup_t     *lookup;

    struct netos_vlan_info  *next;
} netos_vlan_info_t;

typedef struct {
    netos_vlan_info_t *vlan_table;
} netos_vlan_conv_context_t;

#endif

