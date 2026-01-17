#ifndef IDS_PROTOCOLS_ETH_H
#define IDS_PROTOCOLS_ETH_H

#include <stdint.h>
#include <memory>

#include "ids_macro_defs.h"
#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

#define NETOS_IDS_ETH_ALEN 14

struct eth_hdr {
    uint8_t         src_mac[NETOS_IDS_MACADDR_LEN];
    uint8_t         dst_mac[NETOS_IDS_MACADDR_LEN];
    uint16_t        ethertype;

    explicit eth_hdr() { }
    ~eth_hdr() { }

    netos_status serialize(std::shared_ptr<packet_buf> &buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &buf);
    void print();
};

}

#endif

