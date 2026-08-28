#include <stdint.h>
#include <stdio.h>

#include "protocol_const.h"
#include "netos_status.h"
#include "netos_log.h"
#include "eth.h"
#include "arp_hdr.h"
#include "event_info.h"

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
    if (arp_hdr->hwtype != NETOS_ARP_HWTYPE_ETHER) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ARP_INVAL_ETHER);
        return NETOS_STATUS_ARP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &arp_hdr->protocol_type);
    if (arp_hdr->protocol_type != NETOS_ARP_PROTOCOL_TYPE_IPV4) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ARP_INVAL_PROTOCOL);
        return NETOS_STATUS_ARP_MALFORMED_PKT;
    }

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
    netos_log_debug("\t sender_hw_addr: " NETOS_MACADDR_STR "\n",
                                        NETOS_MACADDR_BUF(arp_hdr->sender_hwaddr));
    netos_log_debug("\t sender_protocol_addr:  %x\n", arp_hdr->sender_protocol_addr);
    netos_log_debug("\t target_hw_addr: "NETOS_MACADDR_STR "\n",
                                        NETOS_MACADDR_BUF(arp_hdr->target_hwaddr));
    netos_log_debug("\t target_protocol_addr: %x\n", arp_hdr->target_protocol_addr);
}

