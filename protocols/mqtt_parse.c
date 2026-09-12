#include "netos_status.h"
#include "pkt_buffer.h"
#include "common.h"
#include "mqtt_hdr.h"

static netos_status_t netos_mqtt_decode_connect(netos_mqtt_hdr_t *hdr,
                                                pkt_buffer_t *pkt_buf)
{
    pkt_buffer_decode_2_bytes(pkt_buf,
                              &hdr->connect.protocol_name.protocol_name_len);
    hdr->connect.protocol_name.protocol_name = (uint8_t *)&(pkt_buf->buffer[pkt_buf->offset]);
    pkt_buf->offset += hdr->connect.protocol_name.protocol_name_len;

    pkt_buffer_decode_byte(pkt_buf, &hdr->connect.version);
    pkt_buffer_decode_byte(pkt_buf, &hdr->connect.connect_flags);
    pkt_buffer_decode_2_bytes(pkt_buf, &hdr->connect.keep_alive);
    pkt_buffer_decode_2_bytes(pkt_buf, &hdr->connect.client_id_len);
    hdr->connect.client_id = (uint8_t *)&(pkt_buf->buffer[pkt_buf->offset]);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_mqtt_decode_connect_ack(netos_mqtt_hdr_t *hdr,
                                                    pkt_buffer_t *pkt_buf)
{
    pkt_buffer_decode_byte(pkt_buf, &hdr->connect_ack.reserved);
    pkt_buffer_decode_byte(pkt_buf, &hdr->connect_ack.result_code);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_mqtt_decode_sub_req(netos_mqtt_hdr_t *hdr,
                                                pkt_buffer_t *pkt_buf)
{
    hdr->sub_req.dup = !!(hdr->hdr_flags & 0x08);
    hdr->sub_req.qos_level = (hdr->hdr_flags & 0x06) >> 2;

    pkt_buffer_decode_2_bytes(pkt_buf, &hdr->sub_req.msg_id);
    pkt_buffer_decode_2_bytes(pkt_buf, &hdr->sub_req.sub_topic.topic_len);

    hdr->sub_req.sub_topic.topic_name = (uint8_t *)&(pkt_buf->buffer[pkt_buf->offset]);
    pkt_buf->offset += hdr->sub_req.sub_topic.topic_len;

    pkt_buffer_decode_byte(pkt_buf, &hdr->sub_req.req_qos);

    return NETOS_STATUS_SUCCESS;
}

static const struct {
    uint8_t msg_type;
    netos_status_t (*cmd_encode_callback)(netos_mqtt_hdr_t *hdr,
                                          pkt_buffer_t *pkt_buf);
    netos_status_t (*cmd_decode_callback)(netos_mqtt_hdr_t *hdr,
                                          pkt_buffer_t *pkt_buf);
} mqtt_callbacks[] = {
    {
        NETOS_MQTT_CONNECT_CMD,
        NULL,
        netos_mqtt_decode_connect
    },
    {
        NETOS_MQTT_CONNECT_ACK,
        NULL,
        netos_mqtt_decode_connect_ack
    },
    {
        NETOS_MQTT_SUB_REQ,
        NULL,
        netos_mqtt_decode_sub_req
    }
};

static netos_status_t netos_mqtt_decode_entry(netos_mqtt_hdr_t *hdr,
                                              pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    uint32_t i;

    pkt_buffer_decode_byte(pkt_buf, &hdr->hdr_flags);
    pkt_buffer_decode_byte(pkt_buf, &hdr->msg_len);

    for (i = 0; i < NETOS_SIZEOF_ARRAY(mqtt_callbacks); i ++) {
        uint32_t msg_type = (hdr->hdr_flags & 0xF0) >> 4;

        if (mqtt_callbacks[i].msg_type == msg_type) {
            ret = mqtt_callbacks[i].cmd_decode_callback(hdr, pkt_buf);
            if (ret != NETOS_STATUS_SUCCESS) {
                return ret;
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_mqtt_decode(netos_mqtt_pdu_t *pdu,
                                 pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    uint32_t index = 0;

    while (pkt_buf->offset < pkt_buf->rx_len) {
        ret = netos_mqtt_decode_entry(&pdu->pdu_list[index], pkt_buf);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }
        index ++;
    }

    return NETOS_STATUS_SUCCESS;
}

