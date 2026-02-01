#ifndef PROTOCOLS_L4_TCP_H
#define PROTOCOLS_L4_TCP_H

#include <stdint.h>
#include <memory>

#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

#define NETOS_TCP_HLEN_MIN          5

struct tcp_flags {
    uint32_t            fin:1;
    uint32_t            syn:1;
    uint32_t            rst:1;
    uint32_t            psh:1;
    uint32_t            ack:1;
    uint32_t            urg:1;
    uint32_t            ece:1;
    uint32_t            cwr:1;
    uint32_t            ecn:1;

    explicit tcp_flags() : fin(0),
                           syn(0),
                           rst(0),
                           psh(0),
                           ack(0),
                           urg(0),
                           ece(0),
                           cwr(0),
                           ecn(0)
    {
    }
    ~tcp_flags()
    {
    }
    void print();
} __attribute__ ((__packed__));

struct tcp_hdr {
    uint16_t            src_port;
    uint16_t            dst_port;
    uint32_t            seq_num;
    uint32_t            ack_num;
    tcp_flags           flags;
    uint8_t             hl;
    uint16_t            win_size;
    uint16_t            chksum;
    uint16_t            urg_ptr;

    uint16_t            start_off;
    uint16_t            end_off;
    uint16_t            checksum_off;

    explicit tcp_hdr() : src_port(0),
                         dst_port(0),
                         seq_num(0),
                         ack_num(0),
                         win_size(0),
                         chksum(0),
                         urg_ptr(0),
                         start_off(0),
                         end_off(0),
                         checksum_off(0)
    {
    }

    ~tcp_hdr()
    {
    }

    netos_status serialize(std::shared_ptr<packet_buf> &buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &buf);
    uint16_t checksum(std::shared_ptr<packet_buf> &buf, uint8_t *src_ip, uint8_t *dst_ip);
    void print();
};

}

#endif
