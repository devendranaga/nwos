#include <stdio.h>
#include <stdint.h>

#include "netos_status.h"
#include "pkt_buffer.h"
#include "ipv4.h"

netos_status_t netos_ipv4_decode(netos_ipv4_hdr_t *ipv4_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if ((pkt_buf->offset + NETOS_IPV4_HDR_LEN_DEFAULT) > pkt_buf->rx_len) {
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr->version = (pkt_buf->buffer[pkt_buf->offset] & 0xF0) >> 4;
    ipv4_hdr->header_len = (pkt_buf->buffer[pkt_buf->offset] & 0x0F);
    pkt_buf->offset ++;

    ipv4_hdr->dscp = (pkt_buf->buffer[pkt_buf->offset] & 0xFC) >> 2;
    ipv4_hdr->ecn = (pkt_buf->buffer[pkt_buf->offset] & 0x03);
    pkt_buf->offset ++;

    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->total_len);
    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->identification);

    ipv4_hdr->flags.reseved = !!(pkt_buf->buffer[pkt_buf->offset] & 0x80);
    ipv4_hdr->flags.dont_fragment = !!(pkt_buf->buffer[pkt_buf->offset] & 0x40);
    ipv4_hdr->flags.more_fragment = !!(pkt_buf->buffer[pkt_buf->offset] & 0x20);

    ipv4_hdr->flags.frag_off = ((pkt_buf->buffer[pkt_buf->offset] & 0x1F) << 8) |
                                 pkt_buf->buffer[pkt_buf->offset + 1];
    pkt_buf->offset += 2;

    pkt_buffer_decode_byte(pkt_buf, &ipv4_hdr->ttl);
    pkt_buffer_decode_byte(pkt_buf, &ipv4_hdr->protocol);
    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->hdr_chksum);
    pkt_buffer_decode_4_bytes(pkt_buf, &ipv4_hdr->src_ipaddr);
    pkt_buffer_decode_4_bytes(pkt_buf, &ipv4_hdr->dst_ipaddr);

    return ret;
}
