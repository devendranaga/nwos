#include <stdio.h>
#include "mqtt.h"
#include "netos_log.h"

void *netos_mqtt_init(netos_config_t *config)
{
    netos_mqtt_context_t *ctx;

    ctx = calloc(1, sizeof(netos_mqtt_context_t));
    if (!ctx) {
        return NULL;
    }

    netos_log_info("MQTT Initialized\n");

    return ctx;
}

void netos_mqtt_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf)
{

}

void netos_mqtt_tx(void *ctx, pkt_buffer_t *pkt_buf)
{

}

void netos_mqtt_deinit(void *ctx)
{

}

