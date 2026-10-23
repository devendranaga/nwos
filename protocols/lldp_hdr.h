#ifndef NETOS_LLDP_HDR_H
#define NETOS_LLDP_HDR_H

#include "netos_status.h"
#include "pkt_buffer.h"
#include "protocol_const.h"

#define NETOS_LLDP_MIN_HDR_LEN          2
#define NETOS_LLDP_CHASSIS_SUBTYPE_MAC  4
#define NETOS_LLDP_PORT_SUBTYPE_MAC     3

typedef enum {
    NETOS_LLDP_TYPE_END         = 0,
    NETOS_LLDP_TYPE_CHASSIS_ID  = 1,
    NETOS_LLDP_TYPE_PORT_ID     = 2,
    NETOS_LLDP_TYPE_TTL         = 3,
    NETOS_LLDP_TYPE_SYSNAME     = 5,
    NETOS_LLDP_TYPE_SYSDESC     = 6,
} netos_lldp_type_t;

typedef struct {
    uint8_t chassis_id_subtype;
    uint8_t mac[NETOS_MACADDR_LEN];
} netos_lldp_chassis_t;

typedef struct {
    uint8_t port_id_subtype;
    uint8_t mac[NETOS_MACADDR_LEN];
} netos_lldp_port_t;

typedef struct {
    uint8_t *sys_name;
    uint16_t sys_name_len;
} netos_lldp_sys_name_t;

typedef struct {
    uint8_t *sys_desc;
    uint16_t sys_desc_len;
} netos_lldp_sys_desc_t;

typedef struct {
    netos_lldp_chassis_t    chassis;
    netos_lldp_port_t       port;
    uint16_t                ttl_secs;
    netos_lldp_sys_name_t   sys_name;
    netos_lldp_sys_desc_t   sys_desc;
} netos_lldp_hdr_t;

netos_status_t netos_lldp_decode(netos_lldp_hdr_t *lldp_hdr, pkt_buffer_t *pkt_buf);

#endif

