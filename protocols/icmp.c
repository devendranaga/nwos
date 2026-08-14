#include "netos_status.h"
#include "netos_log.h"
#include "ethertypes.h"
#include "eth.h"
#include "ipv4_hdr.h"
#include "icmp_hdr.h"
#include "egress_controller.h"
#include "icmp.h"

void *netos_icmp_init(network_config_t *config)
{
    netos_icmp_ctx_t *icmp_ctx;

    icmp_ctx = calloc(1, sizeof(netos_icmp_ctx_t));
    if (!icmp_ctx) {
        return NULL;
    }

    icmp_ctx->icmp_pool = netos_buffer_pool_alloc(32);
    if (!icmp_ctx->icmp_pool) {
        goto err;
    }

    return icmp_ctx;

err:
    if (icmp_ctx) {
        free(icmp_ctx);
    }

    return NULL;
}

static void netos_icmp_do_reply(netos_icmp_ctx_t *icmp_ctx,
                                netos_packet_parser_t *parsed_data,
                                pkt_buffer_t *pkt_buf)
{
    netos_icmp_hdr_t *icmp_h;
    netos_icmp_hdr_t reply;
    netos_eth_hdr_t eth_h;
    netos_ipv4_hdr_t ipv4_h;
    pkt_buffer_t *tx_buf;

    tx_buf = netos_buffer_pool_get_buffer(icmp_ctx->icmp_pool);

    pkt_buffer_reset(tx_buf);
    tx_buf->out_intf = pkt_buf->in_intf;

    NETOS_ETH_DEFAULTS(eth_h,
                       parsed_data->eh.src,
                       pkt_buf->in_intf->mac,
                       NETOS_ETHERTYPE_IPV4);
    netos_eth_encode(&eth_h, tx_buf);

    NETOS_IPV4_DEFAULTS(ipv4_h,
                        parsed_data->l3.ipv4_hdr.total_len,
                        parsed_data->l3.ipv4_hdr.identification,
                        parsed_data->l3.ipv4_hdr.protocol,
                        pkt_buf->in_intf->ipaddr,
                        parsed_data->l3.ipv4_hdr.src_ipaddr);
    ipv4_h.gen_checksum = true;

    netos_ipv4_encode(&ipv4_h, tx_buf);

    icmp_h = &parsed_data->l4.icmp_hdr;

    NETOS_ICMP_ECHO_REPLY_DEFAULTS(reply,
                                   icmp_h->u.echo_req.identifier,
                                   icmp_h->u.echo_req.seq_no);
    reply.gen_checksum = true;
    reply.type = NETOS_ICMP_TYPE_ECHO_REPLY;
    reply.code = NETOS_ICMP_CODE_ECHO_REPLY;
    reply.u.echo_reply.data_len = icmp_h->u.echo_req.data_len;
    reply.u.echo_reply.data = icmp_h->u.echo_req.data;

    netos_icmp_encode(&reply, tx_buf);

    tx_buf->out_intf = pkt_buf->in_intf;
    pkt_buffer_set_tx_len_default(tx_buf);

    netos_egress_enque(pkt_buf->in_intf->egress_ctrl,
                       NETOS_EGRESS_ALG_SP,
                       tx_buf);
}

void netos_icmp_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf)
{
    netos_icmp_hdr_t *icmp_h;
    netos_status_t ret;

    /* The checksum for icmp already verified in the decode. */
    ret = netos_icmp_decode(&parsed_data->l4.icmp_hdr, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    icmp_h = &parsed_data->l4.icmp_hdr;

    if (NETOS_ICMP_IS_ECHO_REQ(icmp_h)) {
        netos_icmp_do_reply(ctx, parsed_data, pkt_buf);
    }
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

