#include <arpa/inet.h>
#include <iostream>

#include "network_config.h"
#include "ethertypes.h"
#include "parsed_pkt.h"
#include "protocols.h"
#include "event_mgr.h"
#include "checksum.h"
#include "statistics.h"
#include "logging.h"

namespace netos {

netos_status parsed_pkt::parse_frame()
{
    network_config *config = network_config::instance();
    netos_status ret = netos_status::NETOS_STATUS_SUCCESS;
    uint32_t vlan_index = 0;

    stats->inc_eth_rx_count();

    ret = this->eh.deserialize(this->pkt_buf);
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    this->ethertype = this->eh.ethertype;

    this->n_vlans = 0;

    if (this->ethertype == NETOS_ETHERTYPE_MACSEC) {

        stats->inc_macsec_rx_count();

        ret = this->macsec_h.deserialize(this->pkt_buf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return ret;
        }
        this->pkt_types_present.has_macsec = 1;
        if (this->macsec_h.has_icv_only()) { /* decode the ethertype. */
            this->ethertype = this->macsec_h.ethertype;
        }
    }

    /**
     * Parse VLAN and more tagged.
     */
    if ((this->ethertype == NETOS_ETHERTYPE_VLAN) ||
        (this->ethertype == NETOS_ETHERTYPE_NONSTD_VLAN)) {

        uint32_t double_vlan_tag = 0;

        /**
         * If there are more than one VLAN header, keep
         * parsing them until we have reached a max number of VLANs
         * that we can parse.
         *
         * It can as well be that the number of such tags would be as
         * many because of an attack.
         */
vlan_parse:
        stats->inc_vlan_rx_count();

        ret = this->vh[vlan_index].deserialize(this->pkt_buf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return ret;
        }

        this->pkt_types_present.has_vlan = 1;
        this->ethertype = this->vh[vlan_index].ethertype;

        if ((this->ethertype == NETOS_ETHERTYPE_VLAN) ||
            (this->ethertype == NETOS_ETHERTYPE_NONSTD_VLAN)) {

            double_vlan_tag ++;

            if (vlan_index >= MAX_VLAN_HEADERS) {
                return netos_status::NETOS_STATUS_MALFORMED_PKT;
            }
            goto vlan_parse;
        }

        this->n_vlans = vlan_index + 1;

        if ((double_vlan_tag >= 2) &&
            (config->vlan_config_.drop_double_tagged_vlan)) {
            event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                                event_description::EVENT_DESC_DBL_VLAN_TAG_DROP_DUE_TO_POLICY,
                                                event_protocol_level::EVENT_PROTOCOL_L2_VLAN,
                                                this->pkt_buf->len_);
            return netos_status::NETOS_STATUS_MALFORMED_PKT;
        }
    }

    // Parse the L2 frame
    if (this->is_an_l2_frame() == netos_status::NETOS_STATUS_SUCCESS) {
        ret = this->parse_l2_frame();
    }

    // parse the L3 frame
    if ((ret == netos_status::NETOS_STATUS_SUCCESS) &&
        (this->is_an_l3_frame() == netos_status::NETOS_STATUS_SUCCESS)) {
        ret = this->parse_l3_frame();
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return ret;
        }
    }

    // we finished parsing at L3 itself, no need to do anything more
    if (this->is_an_l3_frame() == netos_status::NETOS_STATUS_SUCCESS) {
        ret = this->parse_l4_frame();
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return ret;
        }
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status parsed_pkt::parse_l2_frame()
{
    netos_status ret;

    switch (this->ethertype) {
        case NETOS_ETHERTYPE_ARP:
            stats->inc_arp_rx_count();

            ret = this->ah.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_arp = 1;
            }
            return ret;
        break;
        case NETOS_ETHERTYPE_MKA:
            stats->inc_mka_rx_count();

            ret = this->dot1x_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_mka = 1;
            }
            return ret;
        break;
        default:
            event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                                event_description::EVENT_DESC_INVAL_L2_PROTOCOL,
                                                event_protocol_level::EVENT_PROTOCOL_L2,
                                                this->pkt_buf->len_);
            return netos_status::NETOS_STATUS_UNSUPPORTED_L2_PROTOCOL;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

/**
 * Parse the L3 headers.
 *
 * 1. IPV4.
 * 2. IPV6.
 */
netos_status parsed_pkt::parse_l3_frame()
{
    netos_status ret = netos_status::NETOS_STATUS_SUCCESS;

    switch (this->ethertype) {
        case NETOS_ETHERTYPE_IPV4:
            stats->inc_ipv4_rx_count();

            ret = this->ipv4_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_ipv4 = 1;
            }
        break;
        case NETOS_ETHERTYPE_IPV6:
            stats->inc_ipv6_rx_count();

            ret = this->ipv6_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_ipv6 = 1;
            }
        break;
        default:
            event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                                event_description::EVENT_DESC_INVAL_L3_PROTOCOL,
                                                event_protocol_level::EVENT_PROTOCOL_L3,
                                                this->pkt_buf->len_);
            return netos_status::NETOS_STATUS_UNSUPPORTED_L3_PROTOCOL;
    }

    return ret;
}

int parsed_pkt::checksum_tcp4()
{
    checksum_pseudo_hdr pseudo_hdr;
    uint32_t src_addr_endian = htonl(this->ipv4_h.src_addr);
    uint32_t dst_addr_endian = htonl(this->ipv4_h.dst_addr);

    pseudo_hdr.fill_tcp(this->tcp_h.start_off,
                        (uint8_t *)&src_addr_endian,
                        (uint8_t *)&dst_addr_endian);

    return netos::checksum(this->pkt_buf, &pseudo_hdr);
}

int parsed_pkt::checksum_udp4()
{
    checksum_pseudo_hdr pseudo_hdr;
    uint32_t src_addr_endian = htonl(this->ipv4_h.src_addr);
    uint32_t dst_addr_endian = htonl(this->ipv4_h.dst_addr);

    pseudo_hdr.fill_udp(this->udp_h.start_off,
                        (uint8_t *)&src_addr_endian,
                        (uint8_t *)&dst_addr_endian);

    return netos::checksum(this->pkt_buf, &pseudo_hdr);
}

/**
 * Parse the following L4 headers.
 *
 * 1. TCP.
 * 2. UDP.
 * 3. ICMP.
 */
netos_status parsed_pkt::parse_l4_frame()
{
    netos_status ret = netos_status::NETOS_STATUS_SUCCESS;

    switch (this->get_protocol()) {
        case NETOS_IP_PROTOCOL_TCP: {
            int verify_checksum = -1;

            stats->inc_tcp_rx_count();

            ret = this->tcp_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_tcp = 1;

                if (this->pkt_types_present.has_ipv4) {
                    verify_checksum = this->checksum_tcp4();
                }
                if (verify_checksum != 0) {
                    return netos_status::NETOS_STATUS_MALFORMED_PKT;
                }
            }
        } break;
        case NETOS_IP_PROTOCOL_UDP: {
            int verify_checksum = -1;

            stats->inc_udp_rx_count();

            ret = this->udp_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_udp = 1;

                if (this->pkt_types_present.has_ipv4) {
                    verify_checksum = this->checksum_udp4();
                }
                if (verify_checksum != 0) {
                    return netos_status::NETOS_STATUS_MALFORMED_PKT;
                }
            }
        } break;
        case NETOS_IP_PROTOCOL_ICMP:
            stats->inc_icmp_rx_count();

            ret = this->icmp_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_icmp = 1;
            }
        break;
        case NETOS_IP_PROTOCOL_ICMPV6:
            stats->inc_icmpv6_rx_count();

            ret = this->icmpv6_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_icmpv6 = 1;

                checksum_pseudo_hdr pseudo_hdr;

                pseudo_hdr.fill_icmpv6(this->icmpv6_h.start_off,
                                       this->ipv6_h.src_addr,
                                       this->ipv6_h.dst_addr);

                /* validate received ICMPv6 checksum. */
                auto verify_checksum = netos::checksum(this->pkt_buf, &pseudo_hdr);
                if (verify_checksum != 0) {
                    event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                                        event_description::EVENT_DESC_INVAL_ICMPV6_CHECKSUM,
                                                        event_protocol_level::EVENT_PROTOCOL_L4_ICMPV6,
                                                        pkt_buf->len_);
                    return netos_status::NETOS_STATUS_MALFORMED_PKT;
                }
            }
        break;
        default:
            return netos_status::NETOS_STATUS_UNSUPPORTED_L4_PROTOCOL;
    }

    return ret;
}

}

