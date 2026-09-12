#ifndef NETOS_TCP_H
#define NETOS_TCP_H

#include "netos_status.h"
#include "netos_config.h"
#include "packet_parser.h"

typedef struct {
    netos_config_t *config;
} netos_tcp_context_t;

void *netos_tcp_initialize(netos_config_t *config);

void netos_tcp_rx_process(void *ctx,
                          netos_packet_parser_t *pkt_parser,
                          pkt_buffer_t *pkt_buf);

void netos_tcp_tx_process(void *ctx,
                          pkt_buffer_t *pkt_buf);

void netos_tcp_deinit(void *ctx);

#endif

