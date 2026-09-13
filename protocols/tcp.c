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

static uint32_t netos_tcp_hash(void *key)
{
    return 0;
}

static bool netos_tcp_compare(void *key1, void *key2)
{
    return true;
}

void *netos_tcp_initialize(netos_config_t *config)
{
    netos_tcp_context_t *tcp_ctx;
    uint32_t i;

    NETOS_PANIC("TCP Init\n");

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

    netos_log_info("TCP Initialized\n");

    return tcp_ctx;

err:
    if (tcp_ctx) {
        free(tcp_ctx);
    }

    return NULL;
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

    return NETOS_STATUS_SUCCESS;
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

}

