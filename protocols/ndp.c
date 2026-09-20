#include <stdio.h>
#include "ndp.h"
#include "packet_parser.h"
#include "netos_config.h"
#include "netos_log.h"
#include "netos_status.h"

void *netos_ndp_init(netos_config_t *config)
{
    netos_ndp_ctx_t *ndp_ctx;

    ndp_ctx = calloc(1, sizeof(netos_ndp_ctx_t));
    if (!ndp_ctx) {
        return NULL;
    }

    ndp_ctx->config = config;

    netos_log_info("NDP initialized\n");

    return ndp_ctx;
}

void netos_ndp_rx(void *ctx,
                  netos_packet_parser_t *pkt_parser,
                  pkt_buffer_t *pkt_buf)
{
}

