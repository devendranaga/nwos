#ifndef IDS_SRC_PARSED_PKT_H
#define IDS_SRC_PARSED_PKT_H

#include <stdio.h>
#include <stdint.h>
#include <string>
#include <memory>
#include <thread>
#include <atomic>

#include "raw_socket.h"
#include "network_interface_config.h"
#include "error_codes.h"
#include "packet_buf.h"
#include "ethertypes.h"
#include "eth.h"
#include "vlan.h"
#include "arp_hdr.h"
#include "macsec.h"
#include "mka.h"
#include "ipv4.h"
#include "ipv6.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
#include "icmpv6.h"

#include "statistics.h"

#define MAX_VLAN_HEADERS 10

namespace netos {

/**
 * Holds the bits that are present in the below parsed_pkt.
 */
struct parsed_pkt_types {
    uint32_t has_vlan   :1;
    uint32_t has_arp    :1;
    uint32_t has_macsec :1;
    uint32_t has_mka    :1;
    uint32_t has_ipv4   :1;
    uint32_t has_ipv6   :1;
    uint32_t has_udp    :1;
    uint32_t has_tcp    :1;
    uint32_t has_icmp   :1;
    uint32_t has_icmpv6 :1;
} __attribute__ ((__packed__));

/**
 * @brief - Holds the entire packet context along with the
 *          parsed headers of the packet and the received buffer.
 */
struct parsed_pkt {
    std::atomic<std::uint32_t>                  ref_count;
    packet_buf                                  *pkt_buf;
    stats_intf                                  *stats;
    std::shared_ptr<raw_socket>                 raw;
    std::shared_ptr<network_interface_config>   intf_config;
    parsed_pkt_types                            pkt_types_present;
    uint16_t                                    ethertype;
    eth_hdr                                     eh;
    vlan_hdr                                    vh[MAX_VLAN_HEADERS];
    uint32_t                                    n_vlans;
    arp_hdr                                     ah;
    macsec_hdr                                  macsec_h;
    ieee8021x_header                            dot1x_h;
    ipv4_hdr                                    ipv4_h;
    ipv6_hdr                                    ipv6_h;
    udp_hdr                                     udp_h;
    tcp_hdr                                     tcp_h;
    icmp_hdr                                    icmp_h;
    icmpv6_hdr                                  icmpv6_h;
    struct parsed_pkt                           *next;

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

    void inc_ref_count() {
        this->ref_count.fetch_add(1, std::memory_order_acq_rel);
    }
    void dec_ref_count() {
        this->ref_count.fetch_sub(1, std::memory_order_acq_rel);
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
            if ((ethertype == NETOS_ETHERTYPE_ARP) ||
                (ethertype == NETOS_ETHERTYPE_MACSEC) ||
                (ethertype == NETOS_ETHERTYPE_MKA)) {
                return netos_status::NETOS_STATUS_SUCCESS;
            }

            return netos_status::NETOS_STATUS_GENERIC_ERROR;
        }

        int checksum_tcp4();
        int checksum_udp4();
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
        std::mutex lock_;
        explicit parsed_pkt_pool() {}
};

}

#endif
