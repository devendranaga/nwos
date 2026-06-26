#include <stdio.h>
#include <stdint.h>

#include "netos_status.h"
#include "pkt_buffer.h"
#include "ipv4_hdr.h"
#include "checksum.h"
#include "event_info.h"

netos_status_t netos_ipv4_decode(netos_ipv4_hdr_t *ipv4_hdr, pkt_buffer_t *pkt_buf)
{
    uint32_t hdr_len;
    uint32_t ipv4_hdr_len;

    if ((pkt_buf->offset + NETOS_IPV4_HDR_LEN_DEFAULT) > pkt_buf->rx_len) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_SHORT_HDR_LEN);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    pkt_buf->ipv4_offset = pkt_buf->offset;

    ipv4_hdr->version = (pkt_buf->buffer[pkt_buf->offset] & 0xF0) >> 4;
    if (ipv4_hdr->version != NETOS_IPV4_VERSION) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_INVAL_VERSION);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr->header_len = (pkt_buf->buffer[pkt_buf->offset] & 0x0F);
    hdr_len = ipv4_hdr->header_len * 4;
    if (hdr_len < NETOS_IPV4_HDR_LEN_DEFAULT) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_INVAL_HDR_LEN);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    pkt_buf->offset ++;

    ipv4_hdr->dscp = (pkt_buf->buffer[pkt_buf->offset] & 0xFC) >> 2;
    ipv4_hdr->ecn = (pkt_buf->buffer[pkt_buf->offset] & 0x03);
    pkt_buf->offset ++;

    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->total_len);
    if (ipv4_hdr->total_len == 0) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_TOTAL_LEN_ZERO);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->identification);

    ipv4_hdr->flags.reserved = !!(pkt_buf->buffer[pkt_buf->offset] & 0x80);
    if (ipv4_hdr->flags.reserved) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_RESERVED_BIT_SET);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr->flags.dont_fragment = !!(pkt_buf->buffer[pkt_buf->offset] & 0x40);
    ipv4_hdr->flags.more_fragment = !!(pkt_buf->buffer[pkt_buf->offset] & 0x20);
    if (ipv4_hdr->flags.dont_fragment && ipv4_hdr->flags.more_fragment) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_DF_MF_SET);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr->flags.frag_off = ((pkt_buf->buffer[pkt_buf->offset] & 0x1F) << 8) |
                                 pkt_buf->buffer[pkt_buf->offset + 1];
    pkt_buf->offset += 2;

    pkt_buffer_decode_byte(pkt_buf, &ipv4_hdr->ttl);
    if (ipv4_hdr->ttl == 0) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_TTL_ZERO);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    pkt_buffer_decode_byte(pkt_buf, &ipv4_hdr->protocol);
    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->hdr_chksum);
    pkt_buffer_decode_4_bytes(pkt_buf, &ipv4_hdr->src_ipaddr);
    pkt_buffer_decode_4_bytes(pkt_buf, &ipv4_hdr->dst_ipaddr);

    if (ipv4_hdr->src_ipaddr == ipv4_hdr->dst_ipaddr) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_SRC_DST_IP_SAME);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr_len = pkt_buf->offset - pkt_buf->ipv4_offset;

    netos_checksum_t chksum = {
        .buffer = &pkt_buf->buffer[pkt_buf->ipv4_offset],
        .len = ipv4_hdr_len
    };

    uint32_t checksum = netos_ipv4_checksum(&chksum);
    if (checksum != 0) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_CHECKSUM_FAILED);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ipv4_encode(netos_ipv4_hdr_t *ipv4_hdr, pkt_buffer_t *pkt_buf)
{
    uint32_t start_off = 0;
    uint32_t checksum_off = 0;

    start_off = pkt_buf->offset;

    pkt_buf->buffer[pkt_buf->offset] = (ipv4_hdr->version << 4);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->header_len);
    pkt_buf->offset ++;

    pkt_buf->buffer[pkt_buf->offset] = (ipv4_hdr->dscp << 2);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->ecn);
    pkt_buf->offset ++;

    pkt_buffer_encode_2_bytes(pkt_buf, ipv4_hdr->total_len);
    pkt_buffer_encode_2_bytes(pkt_buf, ipv4_hdr->identification);
    pkt_buf->buffer[pkt_buf->offset] = (ipv4_hdr->flags.reserved << 8);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->flags.dont_fragment << 7);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->flags.more_fragment << 6);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->flags.frag_off & 0x1f00);
    pkt_buf->offset ++;

    pkt_buf->buffer[pkt_buf->offset] = ipv4_hdr->flags.frag_off & 0x00FF;
    pkt_buf->offset ++;

    pkt_buffer_encode_byte(pkt_buf, ipv4_hdr->ttl);
    pkt_buffer_encode_byte(pkt_buf, ipv4_hdr->protocol);

    checksum_off = pkt_buf->offset;

    pkt_buffer_encode_2_bytes(pkt_buf, ipv4_hdr->hdr_chksum);
    pkt_buffer_encode_4_bytes(pkt_buf, ipv4_hdr->src_ipaddr);
    pkt_buffer_encode_4_bytes(pkt_buf, ipv4_hdr->dst_ipaddr);

    if (ipv4_hdr->gen_checksum) {
        netos_checksum_t chksum = {
            .buffer = &pkt_buf->buffer[start_off],
            .len = pkt_buf->offset - start_off,
        };

        uint32_t checksum = netos_ipv4_checksum(&chksum);
        pkt_buf->buffer[checksum_off] = (checksum & 0xFF00) >> 8;
        pkt_buf->buffer[checksum_off + 1] = (checksum & 0x00FF);
    }

    return NETOS_STATUS_SUCCESS;
}

