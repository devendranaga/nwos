#ifndef NETOS_MQTT_HDR_H
#define NETOS_MQTT_HDR_H

#include <stdint.h>
#include "netos_status.h"
#include "pkt_buffer.h"

#define NETOS_MQTT_CONNECT_CMD  0x0001
#define NETOS_MQTT_CONNECT_ACK  0x0002
#define NETOS_MQTT_PUBLISH      0x0003
#define NETOS_MQTT_SUB_REQ      0x0008
#define NETOS_MQTT_SUB_ACK      0x0009
#define NETOS_MQTT_PING_REQ     0x000C
#define NETOS_MQTT_PING_RESP    0x000D
#define NETOS_MQTT_DISCONNECT   0x000E

#define NETOS_MQTT_PDU_MAX      32

typedef struct {
    uint16_t                        topic_len;
    uint8_t                         *topic_name;
} netos_mqtt_topic_t;

typedef struct {
    netos_mqtt_topic_t              topic;
    uint16_t                        msg_len;
    uint8_t                         *msg;
} netos_mqtt_publish_t;

typedef struct {
    uint8_t                         dup;
    uint8_t                         qos_level;
    uint8_t                         :8;
    uint16_t                        msg_id;
    netos_mqtt_topic_t              sub_topic;
    uint8_t                         req_qos;
} netos_mqtt_sub_req_t;

typedef struct {
    uint16_t                        msg_id;
    uint8_t                         granted_qos;
} netos_mqtt_sub_ack_t;

typedef struct {
    uint16_t                        protocol_name_len;
    uint8_t                         *protocol_name;
} netos_mqtt_protocol_name_t;

typedef struct __attribute__ ((__packed__)) {
    uint8_t                         username        :1;
    uint8_t                         password        :1;
    uint8_t                         will_retain     :1;
    uint8_t                         qos_level       :2;
    uint8_t                         will_flag       :1;
    uint8_t                         clean_session   :1;
    uint8_t                         reserved        :1;
} netos_mqtt_connect_flags_t;

typedef struct {
    netos_mqtt_protocol_name_t      protocol_name;
    uint8_t                         version;
    uint8_t                         connect_flags;
    netos_mqtt_connect_flags_t      d_conn_flags;
    uint16_t                        keep_alive;
    uint16_t                        client_id_len;
    uint8_t                         *client_id;
} netos_mqtt_connect_t;

typedef struct {
    uint8_t                         reserved;
    uint8_t                         result_code;
} netos_mqtt_connect_ack_t;

typedef struct netos_mqtt_hdr {
    uint8_t                         hdr_flags;
    uint8_t                         msg_len;
    union {
        netos_mqtt_connect_t        connect;
        netos_mqtt_connect_ack_t    connect_ack;
        netos_mqtt_sub_req_t        sub_req;
        netos_mqtt_sub_ack_t        sub_ack;
        netos_mqtt_publish_t        publish;
    };
} netos_mqtt_hdr_t;

typedef struct netos_mqtt_pdu {
    uint32_t                        n_pdus;
    netos_mqtt_hdr_t                pdu_list[NETOS_MQTT_PDU_MAX];
} netos_mqtt_pdu_t;

netos_status_t netos_mqtt_decode(netos_mqtt_pdu_t *pdu,
                                 pkt_buffer_t *pkt_buf);

#endif

