#include <stdint.h>

#include "arp.h"

netos_status_t netos_arp_decode(netos_arp_hdr_t *arp_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if ((pkt_buf->offset + NETOS_ARP_HDR_LEN) > pkt_buf->rx_len) {
        return NETOS_STATUS_ARP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &arp_hdr->hwtype);
    pkt_buffer_decode_2_bytes(pkt_buf, &arp_hdr->protocol_type);
    pkt_buffer_decode_byte(pkt_buf, &arp_hdr->hw_addr_len);
    pkt_buffer_decode_byte(pkt_buf, &arp_hdr->protocol_len);
    pkt_buffer_decode_2_bytes(pkt_buf, &arp_hdr->op);
    pkt_buffer_decode_bytes(pkt_buf, arp_hdr->sender_hwaddr, NETOS_MACADDR_LEN);
    pkt_buffer_decode_4_bytes(pkt_buf, &arp_hdr->sender_protocol_addr);
    pkt_buffer_decode_bytes(pkt_buf, arp_hdr->target_hwaddr, NETOS_MACADDR_LEN);
    pkt_buffer_decode_4_bytes(pkt_buf, &arp_hdr->target_protocol_addr);

    return ret;
}
