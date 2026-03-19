#ifndef PROTOCOLS_L4_UDP_H
#define PROTOCOLS_L4_UDP_H

#include <stdint.h>
#include <memory>

#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

#define NETOS_UDP_HDR_LEN_DEFAULT 8

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;

    uint32_t start_off;

    explicit udp_hdr() : src_port(0),
                         dst_port(0),
                         len(0),
                         checksum(0)
    {
    }

    ~udp_hdr()
    {
    }

    [[nodiscard]] netos_status serialize(packet_buf *pkt_buf);
    [[nodiscard]] netos_status deserialize(packet_buf *pkt_buf);
};

}

#endif

