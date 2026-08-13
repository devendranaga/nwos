#include "netos_status.h"
#include "netos_log.h"
#include "icmp_hdr.h"
#include "icmp.h"

void *netos_icmp_init(network_config_t *config)
{
    netos_icmp_ctx_t *icmp_ctx;

    icmp_ctx = calloc(1, sizeof(netos_icmp_ctx_t));
    if (!icmp_ctx) {
        return NULL;
    }

    return icmp_ctx;
}

void netos_icmp_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf)
{
}

void netos_icmp_tx(void *ctx,
                   pkt_buffer_t *pkt_buf)
{
}

void netos_icmp_deinit(void *ctx)
{
    netos_icmp_ctx_t *icmp_ctx;

    icmp_ctx = ctx;
    if (icmp_ctx) {
        free(icmp_ctx);
    }
}

