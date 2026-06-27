#include "netos_status.h"
#include "pkt_buffer.h"
#include "ipv6_hdr.h"
#include "netos_log.h"

netos_status_t netos_ipv6_decode(netos_ipv6_hdr_t *ipv6_hdr,
                                 pkt_buffer_t *pkt_buf)
{
    uint16_t val;

    ipv6_hdr->version = (pkt_buf->buffer[pkt_buf->offset] & 0xF0) >> 4;
    ipv6_hdr->dscp = ((pkt_buf->buffer[pkt_buf->offset] & 0x0F) << 2) |
                     ((pkt_buf->buffer[pkt_buf->offset + 1] & 0xC0) >> 6);
    pkt_buf->offset ++;

    ipv6_hdr->ecn = (pkt_buf->buffer[pkt_buf->offset] & 0x30) >> 4;
    ipv6_hdr->flow_lable = (pkt_buf->buffer[pkt_buf->offset] & 0x0F) << 16;
    pkt_buf->offset ++;

    pkt_buffer_decode_2_bytes(pkt_buf, &val);
    ipv6_hdr->flow_lable |= val;

    pkt_buffer_decode_2_bytes(pkt_buf, &ipv6_hdr->payload_len);
    pkt_buffer_decode_byte(pkt_buf, &ipv6_hdr->nh);
    pkt_buffer_decode_byte(pkt_buf, &ipv6_hdr->hop_limit);
    pkt_buffer_decode_bytes(pkt_buf, ipv6_hdr->src_ipaddr, NETOS_IPV6_ADDR_LEN);
    pkt_buffer_decode_bytes(pkt_buf, ipv6_hdr->dst_ipaddr, NETOS_IPV6_ADDR_LEN);

    netos_ipv6_print(ipv6_hdr);

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

