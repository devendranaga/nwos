#include <stdint.h>
#include <stdio.h>

#include "protocol_const.h"
#include "netos_status.h"
#include "netos_log.h"
#include "arp.h"
#include "eth.h"
#include "event_info.h"
#include "packet_parser.h"
#include "ethertypes.h"

netos_status_t netos_arp_decode(netos_arp_hdr_t *arp_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if ((pkt_buf->offset + NETOS_ARP_HDR_LEN) > pkt_buf->rx_len) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ARP_SHORT_HDR);
        return NETOS_STATUS_ARP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &arp_hdr->hwtype);
    pkt_buffer_decode_2_bytes(pkt_buf, &arp_hdr->protocol_type);
    pkt_buffer_decode_byte(pkt_buf, &arp_hdr->hw_addr_len);
    pkt_buffer_decode_byte(pkt_buf, &arp_hdr->protocol_len);
    pkt_buffer_decode_2_bytes(pkt_buf, &arp_hdr->op);
    pkt_buffer_decode_bytes(pkt_buf, arp_hdr->sender_hwaddr, NETOS_MACADDR_LEN);
    if (NETOS_IS_MULTICAST(arp_hdr->sender_hwaddr)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ARP_INVAL_SENDER_HWADDR);
        return NETOS_STATUS_ARP_MALFORMED_PKT;
    }

    pkt_buffer_decode_4_bytes(pkt_buf, &arp_hdr->sender_protocol_addr);
    if (NETOS_IS_ZERO_IPADDR(arp_hdr->sender_protocol_addr) ||
        NETOS_IS_BROADCAST_IPADDR(arp_hdr->sender_protocol_addr)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ARP_INVAL_SENDER_PROTOCOL_ADDR);
        return NETOS_STATUS_ARP_MALFORMED_PKT;
    }

    pkt_buffer_decode_bytes(pkt_buf, arp_hdr->target_hwaddr, NETOS_MACADDR_LEN);
    pkt_buffer_decode_4_bytes(pkt_buf, &arp_hdr->target_protocol_addr);

    return ret;
}

netos_status_t netos_arp_encode(netos_arp_hdr_t *arp_hdr, pkt_buffer_t *pkt_buf)
{
    pkt_buffer_encode_2_bytes(pkt_buf, arp_hdr->hwtype);
    pkt_buffer_encode_2_bytes(pkt_buf, arp_hdr->protocol_type);
    pkt_buffer_encode_byte(pkt_buf, arp_hdr->hw_addr_len);
    pkt_buffer_encode_byte(pkt_buf, arp_hdr->protocol_len);
    pkt_buffer_encode_2_bytes(pkt_buf, arp_hdr->op);
    pkt_buffer_encode_bytes(pkt_buf, arp_hdr->sender_hwaddr, NETOS_MACADDR_LEN);
    pkt_buffer_encode_4_bytes(pkt_buf, arp_hdr->sender_protocol_addr);
    pkt_buffer_encode_bytes(pkt_buf, arp_hdr->target_hwaddr, NETOS_MACADDR_LEN);
    pkt_buffer_encode_4_bytes(pkt_buf, arp_hdr->target_protocol_addr);

    return NETOS_STATUS_SUCCESS;
}

void netos_arp_print(netos_arp_hdr_t *arp_hdr)
{
    netos_log_debug("ARP:\n");
    netos_log_debug("\t hwtype: %d\n", arp_hdr->hwtype);
    netos_log_debug("\t protocol_type: 0x%04x\n", arp_hdr->protocol_type);
    netos_log_debug("\t hw_addr_len: %d\n", arp_hdr->hw_addr_len);
    netos_log_debug("\t protocol_len: %d\n", arp_hdr->protocol_len);
    netos_log_debug("\t op: %d\n", arp_hdr->op);
    netos_log_debug("\t sender_hw_addr: "NETOS_MACADDR_STR"\n",
                                        NETOS_MACADDR_BUF(arp_hdr->sender_hwaddr));
    netos_log_debug("\t sender_protocol_addr:  %x\n", arp_hdr->sender_protocol_addr);
    netos_log_debug("\t target_hw_addr: "NETOS_MACADDR_STR"\n",
                                        NETOS_MACADDR_BUF(arp_hdr->target_hwaddr));
    netos_log_debug("\t target_protocol_addr: %x\n", arp_hdr->target_protocol_addr);
}

static netos_status_t netos_arp_send_reply(pkt_buffer_t *pkt_buf,
                                           netos_packet_parser_t *pkt_parser,
                                           netos_arp_protocol_t *arp_ctx)
{
    netos_arp_hdr_t arp_h;
    netos_eth_hdr_t eth_h;

    NETOS_ETH_DEFAULTS(eth_h,
                       pkt_parser->eh.dst,
                       pkt_parser->eh.src,
                       NETOS_ETHERTYPE_ARP);

    NETOS_ARP_REPLY_DEFAULTS((&arp_h),
                             pkt_buf->in_intf->mac,
                             pkt_buf->in_intf->ipaddr,
                             pkt_parser->arp_hdr.sender_hwaddr,
                             pkt_parser->arp_hdr.sender_protocol_addr);

    pkt_buffer_reset(pkt_buf);
    pkt_buffer_set_egress_intf_self(pkt_buf);

    netos_eth_encode(&eth_h, pkt_buf);
    netos_arp_encode(&arp_h, pkt_buf);

    pkt_buffer_set_tx_len_default(pkt_buf);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_arp_rx_process_reply(pkt_buffer_t *pkt_buf,
                                                 netos_packet_parser_t *pkt_parser,
                                                 netos_arp_protocol_t *arp_ctx)
{
    // target hardware is us
    if (pkt_parser->arp_hdr.target_protocol_addr == pkt_buf->in_intf->ipaddr) {
        netos_arp_send_reply(pkt_buf, pkt_parser, arp_ctx);
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_arp_rx_process(pkt_buffer_t *pkt_buf,
                                    netos_packet_parser_t *pkt_parser,
                                    netos_arp_protocol_t *arp_ctx)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if (pkt_parser->arp_hdr.op == NETOS_ARP_OP_REPLY) {
        ret = netos_arp_rx_process_reply(pkt_buf, pkt_parser, arp_ctx);
    }

    return ret;
}

