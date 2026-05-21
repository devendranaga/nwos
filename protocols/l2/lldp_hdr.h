#ifndef PROTOCOLS_L2_LLDP_HDR_H
#define PROTOCOLS_L2_LLDP_HDR_H

#include <functional>

#include "error_codes.h"
#include "netos_macros.h"
#include "packet_buf.h"

namespace netos {

#define LLDP_TLV_TYPE_CHASSIS_ID                    0x01
#define LLDP_TLV_TYPE_PORT_ID                       0x02
#define LLDP_TLV_TYPE_TTL_ID                        0x03

#define LLDP_TLV_TYPE_CHASSIS_SUBTYPE_MACADDR       0x04
#define LLDP_TLV_TYPE_CHASSIS_SUBTYPE_MACADDR_LEN   0x07
#define LLDP_TLV_TYPE_PORT_ID_LEN                   0x04
#define LLDP_TLV_TYPE_TTL_ID_LEN                    0x02

#define LLDP_ID_VALID_CHASSIS                       0x00000001
#define LLDP_ID_VALID_PORT_ID                       0x00000002
#define LLDP_ID_VALID_TTL                           0x00000004

struct lldp_tlv_chassis_id {
    uint8_t chassis_subtype;
    uint8_t chassis_id[NETOS_MACADDR_LEN];

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(uint8_t len, packet_buf *pkt_buf);
};

struct lldp_tlv_port_id {
    uint8_t port_id_subtype;
    uint32_t port_id;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(uint8_t len, packet_buf *pkt_buf);
};

struct lldp_tlv_ttl {
    uint16_t seconds;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(uint8_t len, packet_buf *pkt_buf);
};

struct lldp_hdr {
    uint32_t                    valid_ids;
    struct lldp_tlv_chassis_id  chassis_id;
    struct lldp_tlv_port_id     port_id;
    struct lldp_tlv_ttl         ttl;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

}

#endif

