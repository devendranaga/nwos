#ifndef PROTOCOLS_L2_ACF_H
#define PROTOCOLS_L2_ACF_H

#include <stdint.h>

#include "packet_buf.h"
#include "error_codes.h"

#define AVTP_SUBTYPE_TSCF 0x05
#define AVTP_SUBTYPE_NTSCF 0x82
#define AVTP_STREAM_ID_LEN 8

#define NTSCF_STREAM_ID_WITHOUT_RESERVATION 0
#define NTSCF_STREAM_ID_WITH_RESERVATION 1

#define ACF_FLEXRAY 0x00
#define ACF_CAN 0x01
#define ACF_CAN_BRIEF 0x02
#define ACF_LIN 0x03
#define ACF_MOST 0x04
#define ACF_GPC 0x05
#define ACF_SERIAL 0x06
#define ACF_PARALLEL 0x07
#define ACF_SENSOR 0x08
#define ACF_SENSOR_BRIEF 0x09
#define ACF_AECP 0x0A
#define ACF_ANCILIARY 0x0B

#define ACF_CAN_PAYLOAD_LEN 64

namespace netos {

struct ntscf_header_opt {
    uint32_t sv             : 1;
    uint32_t version        : 3;
    uint32_t r              : 1;
    uint32_t ntscf_data_len : 11;
    uint32_t seq_no         : 8;
    uint32_t reserved       : 8;
} __attribute__ ((__packed__));

struct acf_header_opt {
    uint32_t acf_msg_type   : 7;
    uint32_t acf_msg_len    : 9;
} __attribute__ ((__packed__));

struct acf_can_header {
    // padding length
    uint32_t pad            : 2;

    // message timestamp valid
    uint32_t mtv            : 1;
    uint32_t rtr            : 1;
    uint32_t eff            : 1;
    uint32_t brs            : 1;
    uint32_t fdf            : 1;
    uint32_t esi            : 1;
    uint32_t rsv            : 3;
    uint32_t can_bus_id     : 5;
    uint64_t msg_timestamp;
    uint32_t rsv_2          : 3;
    uint32_t can_id         : 29;
    uint8_t can_msg_len;
    uint8_t can_payload[ACF_CAN_PAYLOAD_LEN];

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
} __attribute__ ((__packed__));

struct acf_can_brief_header {
    uint32_t pad            : 2;
    uint32_t mtv            : 1;
    uint32_t rtr            : 1;
    uint32_t eff            : 1;
    uint32_t brs            : 1;
    uint32_t fdf            : 1;
    uint32_t esi            : 1;
    uint32_t rsv            : 3;
    uint32_t can_bus_id     : 5;
    uint32_t can_id         : 29;
    uint32_t rsv_2          : 3;
    uint8_t can_payload[ACF_CAN_PAYLOAD_LEN];
} __attribute__ ((__packed__));

struct ntscf_header {
    ntscf_header_opt        opt;
    uint8_t                 stream_id[AVTP_STREAM_ID_LEN];
    acf_header_opt          acf_opt;
    acf_can_header          *can_hdr;
    acf_can_brief_header    *can_brief_hdr;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

struct tscf_header_opt {
    uint32_t sv                                 :1;
    uint32_t version                            :3;
    uint32_t mr                                 :1;
    uint32_t rsv                                :2;
    uint32_t tv                                 :1;
    uint32_t seq_no                             :8;
    uint32_t rsv_2                              :7;
    uint32_t tu                                 :1;
} __attribute__ ((__packed__));

struct tscf_header {
    tscf_header_opt         opt;
    uint8_t                 stream_id[AVTP_STREAM_ID_LEN];
    uint32_t                avtp_timestamp;
    uint32_t                rsv_1;
    uint16_t                stream_data_len;
    uint16_t                rsv_2;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

struct avtp_header {
    uint8_t                 subtype;
    ntscf_header            *ntscf_h;
    tscf_header             *tscf_h;

    explicit avtp_header() { }
    ~avtp_header() { }

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

}

#endif

