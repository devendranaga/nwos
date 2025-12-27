#ifndef PROTOCOLS_L3_IPV4_H
#define PROTOCOLS_L3_IPV4_H

#include <stdint.h>
#include <memory>

#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

namespace ids {

struct ipv4_flags {
    uint32_t reserved:1;
    uint32_t df:1;
    uint32_t mf:1;
    uint32_t reserved_bits:5;
} __attribute__ ((__packed__));

struct ipv4_hdr {
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t total_len;
    uint16_t id;
    ipv4_flags flags;
    uint32_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_chksum;
    uint32_t src_addr;
    uint32_t dst_addr;

    netos_status serialize(std::shared_ptr<packet_buf> &buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &buf);
};

}

}

#endif

