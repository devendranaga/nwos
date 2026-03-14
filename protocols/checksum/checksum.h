#ifndef PROTOCOLS_CHECKSUM_CHECKSUM_H
#define PROTOCOLS_CHECKSUM_CHECKSUM_H

#include "packet_buf.h"

namespace netos {

/**
 * @brief - pseudo header for L4 and v6 type checksum evaluation or generation.
 */
struct checksum_pseudo_hdr {
    uint32_t    hdr_start_off;
    uint8_t     *src_ipaddr;
    uint8_t     *dst_ipaddr;
    uint8_t     ipaddr_len;
    uint16_t    len;
    uint8_t     protocol;

    /**
     * @brief - setup a pseudo header for the ICMPv6 protocol.
     *
     * @param [in] start_off - start offset in the pkt_buffer.
     * @param [in] src_addr - source ip (v4 or v6) address.
     * @param [in] dst_addr - destination ip (v4 or v6) address.
     */
    void fill_icmpv6(uint32_t start_off, uint8_t *src_addr, uint8_t *dst_addr);
};

uint16_t checksum(packet_buf *pkt_buf, checksum_pseudo_hdr *pseudo_hdr);

}

#endif
