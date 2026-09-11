#include <stdint.h>
#include <stdbool.h>
#include "netos_status.h"
#include "common.h"
#include "pkt_buffer.h"
#include "ipv6_hdr.h"
#include "protocols.h"
#include "netos_log.h"

static netos_status_t netos_ipv6_decode_hop_by_hop_opt(netos_ipv6_hdr_t *ipv6_hdr,
                                                       pkt_buffer_t *pkt_buf)
{
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_ipv6_decode_ipip(netos_ipv6_hdr_t *ipv6_hdr,
                                             pkt_buffer_t *pkt_buf)
{
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_ipv6_decode_routing(netos_ipv6_hdr_t *ipv6_hdr,
                                                pkt_buffer_t *pkt_buf)
{
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_ipv6_decode_frag_hdr(netos_ipv6_hdr_t *ipv6_hdr,
                                                 pkt_buffer_t *pkt_buf)
{
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_ipv6_decode_esp(netos_ipv6_hdr_t *ipv6_hdr,
                                            pkt_buffer_t *pkt_buf)
{
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_ipv6_decode_ah(netos_ipv6_hdr_t *ipv6_hdr,
                                           pkt_buffer_t *pkt_buf)
{
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_ipv6_decode_dest_opt(netos_ipv6_hdr_t *ipv6_hdr,
                                                 pkt_buffer_t *pkt_buf)
{
    return NETOS_STATUS_SUCCESS;
}

static const struct {
    uint8_t opt_type;
    netos_status_t (*decode_opt_callback)(netos_ipv6_hdr_t *ipv6_hdr,
                                          pkt_buffer_t *pkt_buf);
} netos_ipv6_opt_list[] = {
    {
        NETOS_IPV6_NH_HOP_BY_HOP,
        netos_ipv6_decode_hop_by_hop_opt,
    },
    {
        NETOS_IPV6_NH_IPIP,
        netos_ipv6_decode_ipip,
    },
    {
        NETOS_IPV6_NH_ROUTING,
        netos_ipv6_decode_routing,
    },
    {
        NETOS_IPV6_NH_FRAG_HDR,
        netos_ipv6_decode_frag_hdr,
    },
    {
        NETOS_IPV6_NH_ESP,
        netos_ipv6_decode_esp,
    },
    {
        NETOS_IPV6_NH_AH,
        netos_ipv6_decode_ah,
    },
    {
        NETOS_IPV6_NH_DEST_OPT,
        netos_ipv6_decode_dest_opt,
    },
};

const static uint8_t protocol_exceptions[] = {
    NETOS_PROTOCOL_ICMP,
    NETOS_PROTOCOL_TCP,
    NETOS_PROTOCOL_UDP,
    NETOS_PROTOCOL_ICMP6,
}

netos_status_t netos_ipv6_decode(netos_ipv6_hdr_t *ipv6_hdr,
                                 pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    uint16_t val;

    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_IPV6_HDR_LEN_DEFAULT)) {
        return NETOS_STATUS_IPV6_MALFORMED_PKT;
    }

    ipv6_hdr->version = (pkt_buf->buffer[pkt_buf->offset] & 0xF0) >> 4;
    if (ipv6_hdr->version != NETOS_IPV6_VERSION) {
        return NETOS_STATUS_IPV6_MALFORMED_PKT;
    }

    ipv6_hdr->dscp = ((pkt_buf->buffer[pkt_buf->offset] & 0x0F) << 2) |
                     ((pkt_buf->buffer[pkt_buf->offset + 1] & 0xC0) >> 6);
    pkt_buf->offset ++;

    ipv6_hdr->ecn = (pkt_buf->buffer[pkt_buf->offset] & 0x30) >> 4;
    ipv6_hdr->flow_lable = (pkt_buf->buffer[pkt_buf->offset] & 0x0F) << 16;
    pkt_buf->offset ++;

    pkt_buffer_decode_2_bytes(pkt_buf, &val);
    ipv6_hdr->flow_lable |= val;

    pkt_buffer_decode_2_bytes(pkt_buf, &ipv6_hdr->payload_len);
    if (ipv6_hdr->payload_len == 0) {
        return NETOS_STATUS_IPV6_MALFORMED_PKT;
    }

    pkt_buffer_decode_byte(pkt_buf, &ipv6_hdr->nh);
    pkt_buffer_decode_byte(pkt_buf, &ipv6_hdr->hop_limit);
    if (ipv6_hdr->hop_limit == 0) {
        return NETOS_STATUS_IPV6_MALFORMED_PKT;
    }

    pkt_buffer_decode_bytes(pkt_buf, ipv6_hdr->src_ipaddr, NETOS_IPV6_ADDR_LEN);
    pkt_buffer_decode_bytes(pkt_buf, ipv6_hdr->dst_ipaddr, NETOS_IPV6_ADDR_LEN);

    while (pkt_buffer_remaining_rx_len(pkt_buf)) {
        uint32_t i;

        // check if we see the protocol number
        for (i = 0; i < NETOS_SIZEOF_ARRAY(protocol_exceptions); i ++) {
            if (ipv6_hdr->nh == protocol_exceptions[i]) {
                return NETOS_STATUS_SUCCESS;
            }
        }

        // parse the options
        for (i = 0; i < NETOS_SIZEOF_ARRAY(netos_ipv6_opt_list); i ++) {
            if (ipv6_hdr->nh == netos_ipv6_opt_list[i].opt_type) {
                ret = netos_ipv6_opt_list[i].decode_opt_callback(ipv6_hdr, pkt_buf);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return ret;
                }
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ipv6_encode(netos_ipv6_hdr_t *ipv6_hdr,
                                 pkt_buffer_t *pkt_buf)
{
    uint8_t tc;

    pkt_buf->buffer[pkt_buf->offset] = (ipv6_hdr->version << 4);

    tc = ((ipv6_hdr->dscp & 0xFC) << 2) | ipv6_hdr->ecn;
    pkt_buf->buffer[pkt_buf->offset] |= ((tc & 0xF0) >> 4);
    pkt_buf->offset ++;

    pkt_buf->buffer[pkt_buf->offset] = ((tc & 0x0F) << 4);
    pkt_buf->buffer[pkt_buf->offset] |= ((ipv6_hdr->flow_lable & 0x0F0000) >> 16);
    pkt_buf->offset ++;

    pkt_buf->buffer[pkt_buf->offset] = ((ipv6_hdr->flow_lable & 0x00FF00) >> 8);
    pkt_buf->buffer[pkt_buf->offset + 1] = (ipv6_hdr->flow_lable & 0x0000FF);
    pkt_buf->offset += 2;

    pkt_buffer_encode_2_bytes(pkt_buf, ipv6_hdr->payload_len);
    pkt_buffer_encode_byte(pkt_buf, ipv6_hdr->nh);
    pkt_buffer_encode_byte(pkt_buf, ipv6_hdr->hop_limit);
    pkt_buffer_encode_bytes(pkt_buf, ipv6_hdr->src_ipaddr, NETOS_IPV6_ADDR_LEN);
    pkt_buffer_encode_bytes(pkt_buf, ipv6_hdr->dst_ipaddr, NETOS_IPV6_ADDR_LEN);

    return NETOS_STATUS_SUCCESS;
}

void netos_ipv6_print(netos_ipv6_hdr_t *ipv6_hdr)
{
    netos_log_debug("IPv6: {\n");
    netos_log_debug("\t version: %d\n", ipv6_hdr->version);
    netos_log_debug("\t dscp: %d\n", ipv6_hdr->dscp);
    netos_log_debug("\t ecn: %d\n", ipv6_hdr->ecn);
    netos_log_debug("\t flow_lable: %x\n", ipv6_hdr->flow_lable);
    netos_log_debug("\t payload_len %d\n", ipv6_hdr->payload_len);
    netos_log_debug("\t nh: %d\n", ipv6_hdr->nh);
    netos_log_debug("\t hop_limit: %d\n", ipv6_hdr->hop_limit);
    netos_log_debug("\t src_ipaddr: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                        "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                        ipv6_hdr->src_ipaddr[0], ipv6_hdr->src_ipaddr[1],
                        ipv6_hdr->src_ipaddr[2], ipv6_hdr->src_ipaddr[3],
                        ipv6_hdr->src_ipaddr[4], ipv6_hdr->src_ipaddr[5],
                        ipv6_hdr->src_ipaddr[6], ipv6_hdr->src_ipaddr[7],
                        ipv6_hdr->src_ipaddr[8], ipv6_hdr->src_ipaddr[9],
                        ipv6_hdr->src_ipaddr[10], ipv6_hdr->src_ipaddr[11],
                        ipv6_hdr->src_ipaddr[12], ipv6_hdr->src_ipaddr[13],
                        ipv6_hdr->src_ipaddr[14], ipv6_hdr->src_ipaddr[15]);
    netos_log_debug("\t dst_ipaddr: %02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                        "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                        ipv6_hdr->dst_ipaddr[0], ipv6_hdr->dst_ipaddr[1],
                        ipv6_hdr->dst_ipaddr[2], ipv6_hdr->dst_ipaddr[3],
                        ipv6_hdr->dst_ipaddr[4], ipv6_hdr->dst_ipaddr[5],
                        ipv6_hdr->dst_ipaddr[6], ipv6_hdr->dst_ipaddr[7],
                        ipv6_hdr->dst_ipaddr[8], ipv6_hdr->dst_ipaddr[9],
                        ipv6_hdr->dst_ipaddr[10], ipv6_hdr->dst_ipaddr[11],
                        ipv6_hdr->dst_ipaddr[12], ipv6_hdr->dst_ipaddr[13],
                        ipv6_hdr->dst_ipaddr[14], ipv6_hdr->dst_ipaddr[15]);
}

