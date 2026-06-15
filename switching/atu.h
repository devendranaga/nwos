#ifndef NETOS_SWITCHING_ATU_H
#define NETOS_SWITCHING_ATU_H

#include "protocol_const.h"
#include "hash_tables.h"
#include "netos_status.h"

typedef struct {
    uint8_t     mac[NETOS_MACADDR_LEN];
    uint8_t     port;
    uint16_t    vlan_id;
} netos_atu_entry_t;

typedef struct {
    netos_hash_table_t *atu_list;
} netos_atu_context_t;

#endif

