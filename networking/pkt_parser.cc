#include <iostream>

#include "ethertypes.h"
#include "parsed_pkt.h"
#include "protocols.h"
#include "event_mgr.h"
#include "logging.h"

namespace netos {

netos_status parsed_pkt::parse_frame()
{
    netos_status ret = netos_status::NETOS_STATUS_SUCCESS;

    ret = this->eh.deserialize(this->pkt_buf);
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    this->ethertype = this->eh.ethertype;

    if ((this->ethertype == NETOS_ETHERTYPE_VLAN) ||
        (this->ethertype == NETOS_ETHERTYPE_NONSTD_VLAN)) {
        ret = this->vh.deserialize(this->pkt_buf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return ret;
        }
        this->pkt_types_present.has_vlan = 1;
        this->ethertype = this->vh.ethertype;
    }

    // Parse the L2 frame
    if (this->is_an_l2_frame() == netos_status::NETOS_STATUS_SUCCESS) {
        return this->parse_l2_frame();
    } else {
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
            ret = this->ah.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_arp = 1;
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
            ret = this->ipv4_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_ipv4 = 1;
            }
        break;
        case NETOS_ETHERTYPE_IPV6:
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
        case NETOS_IP_PROTOCOL_TCP:
            ret = this->tcp_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_tcp = 1;
            }

            this->tcp_h.checksum(this->pkt_buf, (uint8_t *)&(this->ipv4_h.src_addr), (uint8_t *)&(this->ipv4_h.dst_addr));
        break;
        case NETOS_IP_PROTOCOL_UDP:
            ret = this->udp_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_udp = 1;
            }
        break;
        case NETOS_IP_PROTOCOL_ICMP:
            ret = this->icmp_h.deserialize(this->pkt_buf);
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->pkt_types_present.has_icmp = 1;
            }
        break;
        default:
            return netos_status::NETOS_STATUS_UNSUPPORTED_L4_PROTOCOL;
    }

    return ret;
}

}
