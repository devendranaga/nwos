#include <stdio.h>
#include <stdint.h>

#include "netos_status.h"
#include "pkt_buffer.h"
#include "ipv4_hdr.h"
#include "checksum.h"
#include "event_info.h"
#include "netos_log.h"

netos_status_t netos_ipv4_decode(netos_ipv4_hdr_t *ipv4_hdr, pkt_buffer_t *pkt_buf)
{
    uint32_t hdr_len;
    uint32_t ipv4_hdr_len;

    // short header
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_IPV4_HDR_LEN_DEFAULT)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_SHORT_HDR_LEN);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    pkt_buf->ipv4_offset = pkt_buf->offset;

    ipv4_hdr->version = (pkt_buf->buffer[pkt_buf->offset] & 0xF0) >> 4;
    if (ipv4_hdr->version != NETOS_IPV4_VERSION) { /* invalid IPv4 version. */
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_INVAL_VERSION);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr->header_len = (pkt_buf->buffer[pkt_buf->offset] & 0x0F);
    hdr_len = ipv4_hdr->header_len * 4;
    if (hdr_len < NETOS_IPV4_HDR_LEN_DEFAULT) { /* short header length */
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
    if (ipv4_hdr->total_len == 0) { /* ipv4 payload length is 0. */
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_TOTAL_LEN_ZERO);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->identification);

    ipv4_hdr->flags.reserved = !!(pkt_buf->buffer[pkt_buf->offset] & 0x80);
    if (ipv4_hdr->flags.reserved) { /* reserved bit set. */
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_RESERVED_BIT_SET);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr->flags.dont_fragment = !!(pkt_buf->buffer[pkt_buf->offset] & 0x40);
    ipv4_hdr->flags.more_fragment = !!(pkt_buf->buffer[pkt_buf->offset] & 0x20);
    if (ipv4_hdr->flags.dont_fragment &&
        ipv4_hdr->flags.more_fragment) { /* both df and mf are set. */
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_DF_MF_SET);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr->flags.frag_off = ((pkt_buf->buffer[pkt_buf->offset] & 0x1F) << 8) |
                                 pkt_buf->buffer[pkt_buf->offset + 1];
    pkt_buf->offset += 2;

    pkt_buffer_decode_byte(pkt_buf, &ipv4_hdr->ttl);
    if (ipv4_hdr->ttl == 0) { /* zero ttl. */
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_TTL_ZERO);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    pkt_buffer_decode_byte(pkt_buf, &ipv4_hdr->protocol);
    pkt_buffer_decode_2_bytes(pkt_buf, &ipv4_hdr->hdr_chksum);
    pkt_buffer_decode_4_bytes(pkt_buf, &ipv4_hdr->src_ipaddr);
    pkt_buffer_decode_4_bytes(pkt_buf, &ipv4_hdr->dst_ipaddr);

    if (ipv4_hdr->src_ipaddr == ipv4_hdr->dst_ipaddr) { /* src and dst are same. */
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_IPV4_SRC_DST_IP_SAME);
        return NETOS_STATUS_IPV4_MALFORMED_PKT;
    }

    ipv4_hdr_len = pkt_buf->offset - pkt_buf->ipv4_offset;

    netos_checksum_t chksum = {
        .buffer     = &pkt_buf->buffer[pkt_buf->ipv4_offset],
        .len        = ipv4_hdr_len
    };

    uint32_t checksum = netos_ipv4_checksum(&chksum);
    if (checksum != 0) { /* invalid checksum */
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
    pkt_buf->buffer[pkt_buf->offset] = (ipv4_hdr->flags.reserved << 7);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->flags.dont_fragment << 6);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->flags.more_fragment << 5);
    pkt_buf->buffer[pkt_buf->offset] |= (ipv4_hdr->flags.frag_off & 0x1f00) >> 8;
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

void netos_ipv4_print(netos_ipv4_hdr_t *ipv4_hdr)
{
    netos_log_debug("IPv4: {\n");
    netos_log_debug("\t version: %d\n", ipv4_hdr->version);
    netos_log_debug("\t ihl: %d\n", ipv4_hdr->header_len);
    netos_log_debug("\t dscp: %d\n", ipv4_hdr->dscp);
    netos_log_debug("\t ecn: %d\n", ipv4_hdr->ecn);
    netos_log_debug("\t total_len: %d\n", ipv4_hdr->total_len);
    netos_log_debug("\t id: %d\n", ipv4_hdr->identification);
    netos_log_debug("\t flags:\n");
    netos_log_debug("\t\t reserved: %d\n", ipv4_hdr->flags.reserved);
    netos_log_debug("\t\t dont_fragment: %d\n", ipv4_hdr->flags.dont_fragment);
    netos_log_debug("\t\t more_fragment: %d\n", ipv4_hdr->flags.more_fragment);
    netos_log_debug("\t\t frag_off: %d\n", ipv4_hdr->flags.frag_off);
    netos_log_debug("\t ttl: %d\n", ipv4_hdr->ttl);
    netos_log_debug("\t protocol: %d\n", ipv4_hdr->protocol);
    netos_log_debug("\t hdr_chksum: 0x%04x\n", ipv4_hdr->hdr_chksum);
    netos_log_debug("\t src_ipaddr: 0x%x\n", ipv4_hdr->src_ipaddr);
    netos_log_debug("\t dst_ipaddr: 0x%x\n", ipv4_hdr->dst_ipaddr);
    netos_log_debug("}\n");
}

