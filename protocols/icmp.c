#include "netos_status.h"
#include "netos_log.h"
#include "ethertypes.h"
#include "eth.h"
#include "ipv4_hdr.h"
#include "icmp_hdr.h"
#include "egress_controller.h"
#include "icmp.h"
#include "statistics_ctx.h"
#include "event_info.h"

void *netos_icmp_init(netos_config_t *config)
{
    netos_icmp_ctx_t *icmp_ctx;

    icmp_ctx = calloc(1, sizeof(netos_icmp_ctx_t));
    if (!icmp_ctx) {
        return NULL;
    }

    icmp_ctx->config = config;

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

    // get the tx buffer from the buffer pool
    tx_buf = netos_buffer_pool_get_buffer(icmp_ctx->icmp_pool);
    if (!tx_buf) {
        return;
    }

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
                                   icmp_h->echo_req.identifier,
                                   icmp_h->echo_req.seq_no);

    reply.gen_checksum              = true;
    reply.type                      = NETOS_ICMP_TYPE_ECHO_REPLY;
    reply.code                      = NETOS_ICMP_CODE_ECHO_REPLY;
    reply.echo_reply.data_len     = icmp_h->echo_req.data_len;
    reply.echo_reply.data         = icmp_h->echo_req.data;
    reply.echo_reply.identifier   = icmp_h->echo_req.identifier;
    reply.echo_reply.seq_no       = icmp_h->echo_req.seq_no;

    netos_icmp_encode(&reply, tx_buf);

    pkt_buffer_set_tx_len_default(tx_buf);

    netos_egress_enque(pkt_buf->out_intf->egress_ctrl,
                       NETOS_EGRESS_ALG_SP,
                       tx_buf);

    // increment per interface and aggregated statistics
    netos_statistics_inc_icmp_egress(tx_buf->out_intf->stats_ctx);
    netos_statistics_inc_n_icmp_tx();
}

void netos_icmp_rx(void *ctx,
                   netos_packet_parser_t *parsed_data,
                   pkt_buffer_t *pkt_buf)
{
    netos_icmp_ctx_t *icmp_ctx = ctx;
    netos_icmp_hdr_t *icmp_h;
    netos_status_t ret;

    /* The checksum for icmp already verified in the decode. */
    ret = netos_icmp_decode(&parsed_data->l4.icmp_hdr, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_statistics_inc_n_icmp_rx_dec_errors(pkt_buf->in_intf->stats_ctx);
        return;
    }

    // increment per interface and global statistics of icmp rx
    netos_statistics_inc_icmp_ingress(pkt_buf->in_intf->stats_ctx);
    netos_statistics_inc_n_icmp_rx();

    icmp_h = &parsed_data->l4.icmp_hdr;

    // if its an ipv4 icmp echo request
    // validate against the minimum data length of the echo request payload length
    if (NETOS_ICMP_IS_ECHO_REQ(icmp_h) &&
        NETOS_IS_IPV4_FRAME(parsed_data) &&
        (icmp_h->echo_req.data_len >
         icmp_ctx->config->protocol_config.icmp_config.echo_payload_len)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_ECHO_DATA_LEN_INVAL);
        return;
    }

    // the frame is an IPv4 echo request and that the
    // target address match our ingress interface.
    if (NETOS_ICMP_IS_ECHO_REQ(icmp_h) &&
        NETOS_IS_IPV4_FRAME(parsed_data) &&
        (parsed_data->l3.ipv4_hdr.dst_ipaddr == pkt_buf->in_intf->ipaddr)) {
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
        if (icmp_ctx->icmp_pool) {
            netos_buffer_pool_free(icmp_ctx->icmp_pool);
        }
        free(icmp_ctx);
    }
}

