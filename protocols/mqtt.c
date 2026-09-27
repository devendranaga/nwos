#include <stdio.h>
#include "mqtt_hdr.h"
#include "mqtt.h"
#include "netos_log.h"

void *netos_mqtt_init(netos_config_t *config)
{
    netos_mqtt_context_t *ctx;

    ctx = calloc(1, sizeof(netos_mqtt_context_t));
    if (!ctx) {
        return NULL;
    }

    memset(&ctx->rx_pdu, 0, sizeof(netos_mqtt_pdu_t));

    netos_log_info("MQTT Initialized\n");

    return ctx;
}

void netos_mqtt_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    netos_mqtt_context_t *mqtt_ctx = ctx;

    ret = netos_mqtt_decode(&mqtt_ctx->rx_pdu, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

void netos_mqtt_tx(void *ctx, pkt_buffer_t *pkt_buf)
{

}

void netos_mqtt_deinit(void *ctx)
{

}

