#ifndef NETOS_NDP_H
#define NETOS_NDP_H

#include "netos_config.h"
#include "packet_parser.h"

typedef struct {
    netos_config_t *config;
} netos_ndp_ctx_t;

void *netos_ndp_init(netos_config_t *config);

void netos_ndp_rx(void *ctx,
                  netos_packet_parser_t *pkt_parser,
                  pkt_buffer_t *pkt_buf);

#endif

