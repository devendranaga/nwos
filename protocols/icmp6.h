#ifndef NETOS_ICMP6_H
#define NETOS_ICMP6_H

#include "netos_status.h"
#include "netos_config.h"
#include "packet_parser.h"
#include "buffer_pool.h"

typedef struct {
    netos_config_t    *config;
    netos_buffer_pool_t *icmp6_pool;
} netos_icmp6_ctx_t;

void *netos_icmp6_init(netos_config_t *config);

void netos_icmp6_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf);

void netos_icmp6_tx(void *ctx,
                   pkt_buffer_t *pkt_buf);

void netos_icmp6_deinit(void *ctx);

#endif

