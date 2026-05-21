#ifndef PROTOCOLS_L4_ICMPV6_H
#define PROTOCOLS_L4_ICMPV6_H

#include "error_codes.h"

#define NETOS_ICMPV6_ECHO_REQ                   128
#define NETOS_ICMPV6_ECHO_REPLY                 129

#define NETOS_ICMPV6_HDR_LEN                    4
#define NETOS_ICMPV6_ECHO_REQ_HDR_LEN           4
#define NETOS_ICMPV6_ECHO_REPLY_HDR_LEN         4

namespace netos {

struct icmpv6_echo {
    uint16_t identifier;
    uint16_t sequence;
    uint16_t data_len;
    uint8_t *data;

    explicit icmpv6_echo();
    ~icmpv6_echo();

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
    void print();
};

struct icmpv6_hdr {
    uint32_t start_off;
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    explicit icmpv6_hdr();
    ~icmpv6_hdr();

    icmpv6_echo echo_req;
    icmpv6_echo echo_reply;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
    void print();
};

}

#endif
