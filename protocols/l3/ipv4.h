#ifndef PROTOCOLS_L3_IPV4_H
#define PROTOCOLS_L3_IPV4_H

#include <stdint.h>
#include <memory>

#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

/**
 * @brief - Defines IPV4 version.
 */
#define NETOS_IPV4_VERSION          4

/**
 * @brief - Defines IPV4 default IHL.
 */
#define NETOS_IPV4_IHL_DEFAULT      5

/**
 * @brief - Defines IPV4 flags.
 */
struct ipv4_flags {
    uint32_t            reserved:1;
    uint32_t            df:1;
    uint32_t            mf:1;
    uint32_t            reserved_bits:5;

    explicit ipv4_flags() : reserved(0),
                            df(0),
                            mf(0),
                            reserved_bits(0)
    {
    }
    ~ipv4_flags()
    {
    }

    void print();
} __attribute__ ((__packed__));

/**
 * @brief - Defines IPV4 header.
 */
struct ipv4_hdr {
    uint8_t             version;
    uint8_t             ihl;
    uint8_t             dscp;
    uint8_t             ecn;
    uint16_t            total_len;
    uint16_t            id;
    ipv4_flags          flags;
    uint32_t            frag_off;
    uint8_t             ttl;
    uint8_t             protocol;
    uint16_t            hdr_chksum;
    uint32_t            src_addr;
    uint32_t            dst_addr;

    uint16_t            start_off;
    uint16_t            end_off;
    uint16_t            checksum_off;

    explicit ipv4_hdr() : version(0),
                          ihl(0),
                          dscp(0),
                          ecn(0),
                          total_len(0),
                          id(0),
                          frag_off(0),
                          ttl(0),
                          protocol(0),
                          hdr_chksum(0),
                          src_addr(0),
                          dst_addr(0),
                          start_off(0),
                          end_off(0),
                          checksum_off(0)
    {
    }

    ~ipv4_hdr()
    {
    }

    [[nodiscard]] netos_status serialize(packet_buf *buf);
    [[nodiscard]] netos_status deserialize(packet_buf *buf);
    uint16_t checksum(packet_buf *buf);
    void print();
};

}


#endif

