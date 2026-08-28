#ifndef NETOS_UDP_H
#define NETOS_UDP_H

#include "netos_status.h"
#include "netos_config.h"
#include "packet_parser.h"
#include "buffer_pool.h"

typedef struct {
    netos_config_t *config;
    netos_buffer_pool_t *udp_pool;
} netos_udp_ctx_t;

void *netos_udp_init(netos_config_t *config);

void netos_udp_rx(void *ctx,
                  netos_packet_parser_t *parsed_data,
                  pkt_buffer_t *pkt_buf);

void netos_udp_tx(void *ctx,
                   pkt_buffer_t *pkt_buf);

void netos_udp_deinit(void *ctx);

#endif

