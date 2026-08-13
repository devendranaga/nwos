#ifndef NETOS_ICMP_H
#define NETOS_ICMP_H

#include "netos_status.h"
#include "netos_config.h"
#include "packet_parser.h"

typedef struct {
    network_config_t *config;
} netos_icmp_ctx_t;

void *netos_icmp_init(network_config_t *config);

void netos_icmp_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf);

void netos_icmp_tx(void *ctx,
                   pkt_buffer_t *pkt_buf);

void netos_icmp_deinit(void *ctx);

#endif

