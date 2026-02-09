#ifndef IDS_SRC_PARSED_PKT_H
#define IDS_SRC_PARSED_PKT_H

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <memory>

#include "raw_socket.h"
#include "error_codes.h"
#include "packet_buf.h"
#include "ethertypes.h"
#include "eth.h"
#include "vlan.h"
#include "arp_hdr.h"
#include "ipv4.h"
#include "ipv6.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"

namespace netos {

/**
 * Holds the bits that are present in the below parsed_pkt.
 */
struct parsed_pkt_types {
    uint32_t has_vlan   :1;
    uint32_t has_arp    :1;
    uint32_t has_ipv4   :1;
    uint32_t has_ipv6   :1;
    uint32_t has_udp    :1;
    uint32_t has_tcp    :1;
    uint32_t has_icmp   :1;
} __attribute__ ((__packed__));

/**
 * @brief - Holds the entire packet context along with the
 *          parsed headers of the packet and the received buffer.
 */
struct parsed_pkt {
    packet_buf                  *pkt_buf;
    std::shared_ptr<raw_socket> raw;
    std::string                 ifname;
    parsed_pkt_types            pkt_types_present;
    uint16_t                    ethertype;
    eth_hdr                     eh;
    vlan_hdr                    vh;
    arp_hdr                     ah;
    ipv4_hdr                    ipv4_h;
    ipv6_hdr                    ipv6_h;
    udp_hdr                     udp_h;
    tcp_hdr                     tcp_h;
    icmp_hdr                    icmp_h;
    struct parsed_pkt           *next;

    explicit parsed_pkt() {}
    ~parsed_pkt() {}

    netos_status parse_l4_frame();
    netos_status parse_l3_frame();
    netos_status parse_l2_frame();
    netos_status parse_frame();

    uint32_t get_protocol()
    {
        if (this->pkt_types_present.has_ipv4) {
            return this->ipv4_h.protocol;
        }
        if (this->pkt_types_present.has_ipv6) {
            return this->ipv6_h.nh;
        }
        return 0xFFFFFFFF;
    }

    private:
        netos_status is_an_l3_frame()
        {
            if ((ethertype == NETOS_ETHERTYPE_IPV4) ||
                (ethertype == NETOS_ETHERTYPE_IPV6)) {
                return netos_status::NETOS_STATUS_SUCCESS;
            }

            return netos_status::NETOS_STATUS_GENERIC_ERROR;
        }

        netos_status is_an_l2_frame()
        {
            if (ethertype == NETOS_ETHERTYPE_ARP) {
                return netos_status::NETOS_STATUS_SUCCESS;
            }

            return netos_status::NETOS_STATUS_GENERIC_ERROR;
        }
};

class parsed_pkt_pool {
    public:
        static parsed_pkt_pool *instance() {
            static parsed_pkt_pool pool;
            return &pool;
        }
        ~parsed_pkt_pool() {}

        netos_status initialize(uint32_t size);
        parsed_pkt *get_pkt();
        void put_pkt(parsed_pkt *pkt);

    private:
        uint32_t size_;
        parsed_pkt *head_;
        explicit parsed_pkt_pool() {}
};

}

#endif
