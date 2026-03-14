#ifndef PROTOCOLS_L3_IPV6_H
#define PROTOCOLS_L3_IPV6_H

#include <stdint.h>
#include <memory>
#include <cstring>

#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

#define NETOS_IPV6_VERSION          6

#define NETOS_IPV6_NH_FRAG_HDR      44
#define NETOS_IPV6_NH_ICMPV6        58

#define NETOS_IPV6_FRAG_HDR_LEN     8

struct ipv6_frag_hdr {
    uint8_t     next_hdr;           /* 1 byte. */
    uint8_t     reserved;           /* 1 byte. */
    uint16_t    frag_off;           /* 13 bits. */
    uint8_t     reserved_2;         /* 2 bits. */
    uint8_t     more_fragments;     /* 1 bit. */
    uint32_t    identification;     /* 4 bytes. */

    explicit ipv6_frag_hdr() { }
    ~ipv6_frag_hdr() { }

    netos_status serialize(packet_buf *buf);
    netos_status deserialize(packet_buf *buf, event_mgr *evt_mgr, uint8_t *nh);
    void print();
};

struct ipv6_hdr {
    uint32_t            version:4;
    uint32_t            traffic_class:8;
    uint32_t            flow_label:20;
    uint16_t            payload_len;
    uint8_t             nh;
    uint8_t             hop_limit;
    uint8_t             src_addr[16];
    uint8_t             dst_addr[16];

    uint16_t            start_off;
    uint16_t            end_off;

    ipv6_frag_hdr       *frag_hdr;

    explicit ipv6_hdr() : version(0),
                          traffic_class(0),
                          flow_label(0),
                          payload_len(0),
                          nh(0),
                          hop_limit(0),
                          start_off(0),
                          end_off(0)
    {
        std::memset(src_addr, 0, 16);
        std::memset(dst_addr, 0, 16);
    }

    ~ipv6_hdr()
    {
    }

    [[nodiscard]] netos_status serialize(packet_buf *buf);
    [[nodiscard]] netos_status deserialize(packet_buf *buf);
};

}

#endif
