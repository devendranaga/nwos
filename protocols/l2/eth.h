#ifndef IDS_PROTOCOLS_ETH_H
#define IDS_PROTOCOLS_ETH_H

#include <stdint.h>
#include <memory>

#include "netos_macros.h"
#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

#define NETOS_ETH_ALEN 14

struct eth_hdr {
    uint8_t         src_mac[NETOS_MACADDR_LEN];
    uint8_t         dst_mac[NETOS_MACADDR_LEN];
    uint16_t        ethertype;

    explicit eth_hdr() { }
    ~eth_hdr() { }

    netos_status serialize(packet_buf *buf);
    netos_status deserialize(packet_buf *buf);
    void print();
};

}

#endif

