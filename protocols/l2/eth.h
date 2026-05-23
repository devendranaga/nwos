#ifndef IDS_PROTOCOLS_ETH_H
#define IDS_PROTOCOLS_ETH_H

#include <stdint.h>
#include <memory>

#include "netos_macros.h"
#include "packet_buf.h"
#include "error_codes.h"

namespace netos {

#define NETOS_ETH_ALEN 14

/**
 * @brief - Defines Ethernet Header.
 */
struct eth_hdr {
    uint8_t         src_mac[NETOS_MACADDR_LEN];
    uint8_t         dst_mac[NETOS_MACADDR_LEN];
    uint16_t        ethertype;

    explicit eth_hdr() { }

    /**
     * @brief - initialize ethernet header.
     *
     * @param [in] dst_mac - destination mac.
     * @param [in] src_mac - source mac.
     * @param [in] ethertype - ethertype.
     */
    explicit eth_hdr(uint8_t *dst_mac, uint8_t *src_mac, uint16_t ethertype) {
        memcpy(this->dst_mac, dst_mac, NETOS_MACADDR_LEN);
        memcpy(this->src_mac, src_mac, NETOS_MACADDR_LEN);
        this->ethertype = ethertype;
    }
    ~eth_hdr() { }

    netos_status serialize(packet_buf *buf);
    netos_status deserialize(packet_buf *buf);
    void print();
};

}

#endif

