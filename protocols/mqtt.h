#ifndef NETOS_MQTT_H
#define NETOS_MQTT_H

#include "netos_config.h"
#include "packet_parser.h"

typedef struct {
    netos_config_t *config;
} netos_mqtt_context_t;

void *netos_mqtt_init(netos_config_t *config);

void netos_mqtt_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf);

void netos_mqtt_tx(void *ctx, pkt_buffer_t *pkt_buf);

void netos_mqtt_deinit(void *ctx);

#endif
