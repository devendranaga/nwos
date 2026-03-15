#include "netos_macros.h"
#include "protocols.h"
#include "checksum.h"

namespace netos {

uint16_t checksum(packet_buf *pkt_buf, checksum_pseudo_hdr *pseudo_hdr)
{
    uint32_t chksum32 = 0;
    uint32_t i = 0;
    uint32_t pad = 0;

    if ((pkt_buf->len_ - pseudo_hdr->hdr_start_off) % 2) {
        pad = 1;
    }

    for (i = 0; i < pseudo_hdr->ipaddr_len; i += 2) {
        chksum32 += (pseudo_hdr->src_ipaddr[i + 1]) + (pseudo_hdr->src_ipaddr[i] << 8);
    }

    for (i = 0; i < pseudo_hdr->ipaddr_len; i += 2) {
        chksum32 += (pseudo_hdr->dst_ipaddr[i + 1]) + (pseudo_hdr->dst_ipaddr[i] << 8);
    }

    // packet Length
    uint32_t pkt_len = pkt_buf->len_ - pseudo_hdr->hdr_start_off;

    chksum32 += (pkt_len & 0x0000FFFFu) + ((pkt_len & 0xFFFF0000u) >> 16);

    // Protocol (6, 17, 58)
    chksum32 += pseudo_hdr->protocol;

    // Payload Checksum
    for (i = pseudo_hdr->hdr_start_off; i <= pkt_buf->len_ + pad; i += 2) {
        if (i < pkt_buf->len_ - 1) {
            chksum32 += ((pkt_buf->buf_[i] << 8) | (pkt_buf->buf_[i + 1]));
        } else {
            // Odd byte padding
            chksum32 += pkt_buf->buf_[i] << 8;
        }
    }

    // Fold 32-bit sum to 16-bit
    if (chksum32 > 0xFFFFu) {
        chksum32 = ((chksum32 & 0xFFFF0000) >> 16) + (chksum32 & 0x0000FFFF);
    }

    return ~chksum32;
}

void checksum_pseudo_hdr::fill_icmpv6(uint32_t start_off,
                                      uint8_t *src_addr,
                                      uint8_t *dst_addr)
{
    this->hdr_start_off     = start_off;
    this->src_ipaddr        = src_addr;
    this->dst_ipaddr        = dst_addr;
    this->ipaddr_len        = NETOS_IPV6_ADDR_LEN;
    this->protocol          = NETOS_IP_PROTOCOL_ICMPV6;
}

void checksum_pseudo_hdr::fill_udp(uint32_t start_off,
                                   uint8_t *src_addr,
                                   uint8_t *dst_addr)
{
    this->hdr_start_off     = start_off;
    this->src_ipaddr        = src_addr;
    this->dst_ipaddr        = dst_addr;
    this->ipaddr_len        = NETOS_IPV4_ADDR_LEN;
    this->protocol          = NETOS_IP_PROTOCOL_UDP;
}

void checksum_pseudo_hdr::fill_tcp(uint32_t start_off,
                                   uint8_t *src_addr,
                                   uint8_t *dst_addr)
{
    this->hdr_start_off     = start_off;
    this->src_ipaddr        = src_addr;
    this->dst_ipaddr        = dst_addr;
    this->ipaddr_len        = NETOS_IPV4_ADDR_LEN;
    this->protocol          = NETOS_IP_PROTOCOL_TCP;
}

}

