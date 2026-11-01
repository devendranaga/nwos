#include <stdio.h>
#include "netos_status.h"
#include "netos_config.h"
#include "common.h"
#include "event_info.h"
#include "checksum_l4.h"
#include "port_numbers.h"
#include "packet_parser.h"
#include "mqtt.h"
#include "tcp_hdr.h"
#include "tcp.h"
#include "statistics_ctx.h"
#include "netos_log.h"

static struct {
    bool        valid;
    uint16_t    dest_port;
    void        *protocol_ctx;
    void        *(*init)(netos_config_t *config);
    void        (*rx)(void *ctx,
                      netos_packet_parser_t *parsed_data,
                      pkt_buffer_t *pkt_buf);
    void        (*tx)(void *ctx,
                      pkt_buffer_t *pkt_buf);
    void        (*deinit)(void *ctx);
} application_callbacks[] = {
    {
        true,
        NETOS_PORT_NUM_MQTT,
        NULL,
        netos_mqtt_init,
        netos_mqtt_rx,
        netos_mqtt_tx,
        netos_mqtt_deinit
    }
};

static uint32_t netos_tcp_hash_easy(netos_tcp_conn_key_t *conn_key)
{
    uint32_t hash;
    uint32_t i;

    hash = conn_key->protocol;

    if (conn_key->is_ipv4) {
        hash += conn_key->v4.src_ip + conn_key->v4.dst_ip;
    } else {
        for (i = 0; i < NETOS_IPV6_ADDR_LEN / 4; i ++) {
            hash += *(uint32_t *)(conn_key->v6.src_ip + i);
        }
        for (i = 0; i < NETOS_IPV6_ADDR_LEN / 4; i ++) {
            hash += *(uint32_t *)(conn_key->v6.dst_ip + i);
        }
    }

    hash += conn_key->src_port;
    hash += conn_key->dst_port;

    return hash;
}

static uint32_t netos_tcp_hash(void *key)
{
    netos_tcp_conn_key_t *conn_key = key;

    return netos_tcp_hash_easy(conn_key);
}

static bool netos_tcp_compare(void *key1, void *key2)
{
    return true;
}

static bool netos_tcp_del_conn_cb(void *key, void *val)
{
    return true;
}

void *netos_tcp_initialize(netos_config_t *config)
{
    netos_tcp_context_t *tcp_ctx;
    uint32_t i;

    tcp_ctx = calloc(1, sizeof(netos_tcp_context_t));
    if (!tcp_ctx) {
        NETOS_PANIC("cannot allocate memory\n");
        return NULL;
    }

    tcp_ctx->config     = config;
    tcp_ctx->conn_list  = netos_hash_table_init(NETOS_TCP_CONN_LIST_MAX,
                                                netos_tcp_hash,
                                                netos_tcp_compare);
    if (!tcp_ctx->conn_list) {
        goto err;
    }

    for (i = 0; i < NETOS_SIZEOF_ARRAY(application_callbacks); i ++) {
        if (application_callbacks[i].valid &&
            application_callbacks[i].init) {
            application_callbacks[i].protocol_ctx =
                        application_callbacks[i].init(config);
        }
    }

    return tcp_ctx;

err:
    if (tcp_ctx) {
        free(tcp_ctx);
    }

    return NULL;
}

static netos_tcp_connection_t *netos_tcp_conn_add(netos_tcp_context_t *ctx,
                                         netos_packet_parser_t *parsed_data,
                                         netos_tcp_conn_key_t *key)
{
    netos_tcp_connection_t *conn;
    netos_tcp_conn_key_t *key_ptr;
    netos_status_t ret;

    key_ptr = calloc(1, sizeof(netos_tcp_conn_key_t));
    if (!key_ptr) {
        return NULL;
    }

    key_ptr->protocol = key->protocol;
    key_ptr->is_ipv4 = key->is_ipv4;
    key_ptr->v4.src_ip = key->v4.src_ip;
    key_ptr->v4.dst_ip = key->v4.dst_ip;
    key_ptr->src_port = key->src_port;
    key_ptr->dst_port = key->dst_port;

    conn = calloc(1, sizeof(netos_tcp_connection_t));
    if (!conn) {
        goto err;
    }

    conn->is_ipv4 = key_ptr->is_ipv4;
    conn->v4.src_ip = key_ptr->v4.src_ip;
    conn->v4.dst_ip = key_ptr->v4.dst_ip;

    clock_gettime(CLOCK_MONOTONIC, &conn->last_updated);

    conn->seq_no = parsed_data->l4.tcp_hdr.seq_no;
    conn->ack_no = parsed_data->l4.tcp_hdr.ack_no;
    conn->src_port = key_ptr->src_port;
    conn->dst_port = key_ptr->dst_port;
    conn->state = NETOS_TCP_STATE_INIT;

    ret = netos_hash_item_add(ctx->conn_list, key_ptr, conn);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    return conn;

err:
    if (conn) {
        free(conn);
    }
    if (key_ptr) {
        free(key_ptr);
    }

    return NULL;
}

static netos_tcp_state_t netos_tcp_state_init(netos_tcp_context_t *ctx,
                                              netos_packet_parser_t *parsed_data,
                                              pkt_buffer_t *pkt_buf)
{
    return NETOS_TCP_STATE_INIT;
}

static netos_tcp_state_t netos_tcp_state_client_sent_syn(
                                        netos_tcp_context_t *ctx,
                                        netos_packet_parser_t *parsed_data,
                                        pkt_buffer_t *pkt_buf)
{
    return NETOS_TCP_STATE_CLIENT_SENT_SYN;
}

static netos_tcp_state_t netos_tcp_state_server_sent_syn_ack(
                                        netos_tcp_context_t *ctx,
                                        netos_packet_parser_t *parsed_data,
                                        pkt_buffer_t *pkt_buf)
{
    return NETOS_TCP_STATE_SERVER_SENT_SYN_ACK;
}

static netos_tcp_state_t netos_tcp_state_conn_established(
                                        netos_tcp_context_t *ctx,
                                        netos_packet_parser_t *parsed_data,
                                        pkt_buffer_t *pkt_buf)
{
    return NETOS_TCP_STATE_CONN_ESTABLISHED;
}

static netos_tcp_state_t netos_tcp_state_fin_sent(
                                        netos_tcp_context_t *ctx,
                                        netos_packet_parser_t *parsed_data,
                                        pkt_buffer_t *pkt_buf)
{
    return NETOS_TCP_STATE_FIN_SENT;
}

static netos_tcp_state_t netos_tcp_state_fin_ack_sent(
                                        netos_tcp_context_t *ctx,
                                        netos_packet_parser_t *parsed_data,
                                        pkt_buffer_t *pkt_buf)
{
    return NETOS_TCP_STATE_FIN_ACK_SENT;
}

static netos_tcp_state_t netos_tcp_state_conn_closed(
                                        netos_tcp_context_t *ctx,
                                        netos_packet_parser_t *parsed_data,
                                        pkt_buffer_t *pkt_buf)
{
    return NETOS_TCP_STATE_CLOSED;
}

static const struct {
    netos_tcp_state_t       state;
    netos_tcp_state_t       (*callback)(netos_tcp_context_t *ctx,
                                        netos_packet_parser_t *parsed_data,
                                        pkt_buffer_t *pkt_buf);
} tcp_statemachine_callbacks[] = {
    {
        NETOS_TCP_STATE_INIT,
        netos_tcp_state_init,
    },
    {
        NETOS_TCP_STATE_CLIENT_SENT_SYN,
        netos_tcp_state_client_sent_syn,
    },
    {
        NETOS_TCP_STATE_SERVER_SENT_SYN_ACK,
        netos_tcp_state_server_sent_syn_ack,
    },
    {
        NETOS_TCP_STATE_CONN_ESTABLISHED,
        netos_tcp_state_conn_established,
    },
    {
        NETOS_TCP_STATE_FIN_SENT,
        netos_tcp_state_fin_sent,
    },
    {
        NETOS_TCP_STATE_FIN_ACK_SENT,
        netos_tcp_state_fin_ack_sent,
    },
    {
        NETOS_TCP_STATE_CLOSED,
        netos_tcp_state_conn_closed
    }
};

/**
 * @brief - Defines TCP statemachine.
 *
 * @param [in] ctx - TCP context.
 * @param [in] parsed_data - parsed packet.
 * @param [in] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
static netos_status_t netos_tcp_state_machine(netos_tcp_context_t *ctx,
                                              netos_packet_parser_t *parsed_data,
                                              pkt_buffer_t *pkt_buf)
{
    netos_tcp_conn_key_t key;
    netos_tcp_connection_t *conn;
    netos_status_t ret = NETOS_STATUS_SUCCESS;
    uint32_t i;

    key.protocol = NETOS_PROTOCOL_TCP;
    key.is_ipv4 = true;
    key.v4.src_ip = parsed_data->l3.ipv4_hdr.src_ipaddr;
    key.v4.dst_ip = parsed_data->l3.ipv4_hdr.dst_ipaddr;
    key.src_port = parsed_data->l4.tcp_hdr.src_port;
    key.dst_port = parsed_data->l4.tcp_hdr.dst_port;

    conn = netos_hash_item_find(ctx->conn_list, &key);
    if (!conn) {
        // add entry
        conn = netos_tcp_conn_add(ctx, parsed_data, &key);
        if (!conn) {
            return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
        }
    }

    for (i = 0; i < NETOS_SIZEOF_ARRAY(tcp_statemachine_callbacks); i ++) {
        if (tcp_statemachine_callbacks[i].state == conn->state) {
            conn->state = tcp_statemachine_callbacks[i].callback(ctx, parsed_data, pkt_buf);
        }
    }

    return ret;
}

static netos_status_t netos_tcp_rx_decode(void *ctx,
                                          netos_packet_parser_t *parsed_data,
                                          pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    uint16_t start_off;
    uint16_t remaining_len;

    start_off       = pkt_buf->offset;
    remaining_len   = pkt_buffer_remaining_rx_len(pkt_buf);

    ret = netos_tcp_decode(&parsed_data->l4.tcp_hdr, pkt_buf);
    if (ret == NETOS_STATUS_SUCCESS) {
        ret = netos_do_checksum_l4(start_off,
                                   remaining_len,
                                   parsed_data,
                                   pkt_buf);
        if (ret != NETOS_STATUS_SUCCESS) {
            NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                       NETOS_EVENT_TYPE_DENY,
                                       NETOS_EVENT_DESC_TCP_CHECKSUM_VERIFY_FAILED);
            return ret;
        }
    }

    return ret;
}

void netos_tcp_rx_process(void *ctx,
                          netos_packet_parser_t *pkt_parser,
                          pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    uint32_t i;

    // decode TCP header
    ret = netos_tcp_rx_decode(ctx, pkt_parser, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    netos_statistics_inc_tcp_ingress(pkt_buf->in_intf->stats_ctx);

    netos_tcp_state_machine(ctx, pkt_parser, pkt_buf);

    for (i = 0; i < NETOS_SIZEOF_ARRAY(application_callbacks); i ++) {
        if (application_callbacks[i].valid &&
            (pkt_parser->l4.tcp_hdr.dst_port ==
             application_callbacks[i].dest_port)) {
            application_callbacks[i].rx(
                                application_callbacks[i].protocol_ctx,
                                pkt_parser,
                                pkt_buf);
        }
    }
}

void netos_tcp_tx_process(void *ctx, pkt_buffer_t *pkt_buf)
{

}

void netos_tcp_deinit(void *ctx)
{
    netos_tcp_context_t *tcp_ctx = ctx;
    uint32_t i;

    if (tcp_ctx) {
        for (i = 0; i < NETOS_SIZEOF_ARRAY(application_callbacks); i ++) {
            if (application_callbacks[i].valid &&
                application_callbacks[i].deinit) {
                application_callbacks[i].deinit(application_callbacks[i].protocol_ctx);
            }
        }
        if (tcp_ctx->conn_list) {
            netos_hash_table_deinit(tcp_ctx->conn_list,
                                    netos_tcp_del_conn_cb);
        }
        free(tcp_ctx);
    }
}

