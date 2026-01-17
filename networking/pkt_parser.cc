#include <iostream>

#include "ethertypes.h"
#include "parsed_pkt.h"
#include "protocols.h"
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
        this->ethertype = this->vh.ethertype;
    }

    ret = this->parse_l3_frame();
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    ret = this->parse_l4_frame();
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status parsed_pkt::parse_l3_frame()
{
    netos_status ret = netos_status::NETOS_STATUS_SUCCESS;

    switch (this->ethertype) {
        case NETOS_ETHERTYPE_IPV4:
            ret = this->ipv4_h.deserialize(this->pkt_buf);
        break;
        case NETOS_ETHERTYPE_IPV6:
            ret = this->ipv6_h.deserialize(this->pkt_buf);
        break;
        default:
            return netos_status::NETOS_STATUS_UNSUPPORTED_L3_PROTOCOL;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status parsed_pkt::parse_l4_frame()
{
    netos_status ret = netos_status::NETOS_STATUS_SUCCESS;

    switch (this->get_protocol()) {
        case NETOS_IP_PROTOCOL_TCP:
            ret = this->tcp_h.deserialize(this->pkt_buf);
        break;
        case NETOS_IP_PROTOCOL_UDP:
            ret = this->udp_h.deserialize(this->pkt_buf);
        break;
        default:
            return netos_status::NETOS_STATUS_UNSUPPORTED_L4_PROTOCOL;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

}
