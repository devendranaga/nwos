#include "netos_status.h"
#include "netos_log.h"
#include "ethertypes.h"
#include "eth.h"
#include "ipv6_hdr.h"
#include "icmp6_hdr.h"
#include "egress_controller.h"
#include "icmp6.h"

void *netos_icmp6_init(netos_config_t *config)
{
    netos_icmp6_ctx_t *icmp6_ctx;

    icmp6_ctx = calloc(1, sizeof(netos_icmp6_ctx_t));
    if (!icmp6_ctx) {
        return NULL;
    }

    icmp6_ctx->icmp6_pool = netos_buffer_pool_alloc(32);
    if (!icmp6_ctx->icmp6_pool) {
        goto err;
    }

    return icmp6_ctx;

err:
    if (icmp6_ctx) {
        free(icmp6_ctx);
    }

    return NULL;
}

static void netos_icmp6_do_reply(netos_icmp6_ctx_t *icmp6_ctx,
                                netos_packet_parser_t *parsed_data,
                                pkt_buffer_t *pkt_buf)
{
}

void netos_icmp6_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf)
{
    netos_icmp6_hdr_t *icmp6_h;
    netos_status_t ret;

    /* The checksum for icmp already verified in the decode. */
    ret = netos_icmp6_decode(&parsed_data->l4.icmp6_hdr, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    icmp6_h = &parsed_data->l4.icmp6_hdr;

    if (NETOS_ICMP6_IS_ECHO_REQ(icmp6_h)) {
        netos_icmp6_do_reply(ctx, parsed_data, pkt_buf);
    }
}

void netos_icmp6_tx(void *ctx,
                   pkt_buffer_t *pkt_buf)
{
}

void netos_icmp6_deinit(void *ctx)
{
    netos_icmp6_ctx_t *icmp6_ctx;

    icmp6_ctx = ctx;
    if (icmp6_ctx) {
        free(icmp6_ctx);
    }
}

