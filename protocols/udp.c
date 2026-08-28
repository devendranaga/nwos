#include "netos_status.h"
#include "netos_log.h"
#include "ethertypes.h"
#include "eth.h"
#include "ipv4_hdr.h"
#include "udp_hdr.h"
#include "egress_controller.h"
#include "udp.h"

void *netos_udp_init(netos_config_t *config)
{
    netos_udp_ctx_t *udp_ctx;

    udp_ctx = calloc(1, sizeof(netos_udp_ctx_t));
    if (!udp_ctx) {
        return NULL;
    }

    udp_ctx->udp_pool = netos_buffer_pool_alloc(32);
    if (!udp_ctx->udp_pool) {
        goto err;
    }

    return udp_ctx;

err:
    if (udp_ctx) {
        free(udp_ctx);
    }

    return NULL;
}

void netos_udp_rx(void *ctx,
                  netos_packet_parser_t *parsed_data,
                  pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;

    /* The checksum for udp already verified in the decode. */
    ret = netos_udp_decode(&parsed_data->l4.udp_hdr, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

void netos_udp_tx(void *ctx,
                   pkt_buffer_t *pkt_buf)
{
}

void netos_udp_deinit(void *ctx)
{
    netos_udp_ctx_t *udp_ctx;

    udp_ctx = ctx;
    if (udp_ctx) {
        free(udp_ctx);
    }
}

