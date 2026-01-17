#include "arp.h"
#include "protocol_util.h"
#include "ethertypes.h"
#include "event_mgr.h"

using namespace netos::ids;

namespace netos {

netos_status arp_hdr::serialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    pkt_buf->serialize_2_bytes(this->hw_type);
    pkt_buf->serialize_2_bytes(this->protocol_type);
    pkt_buf->serialize_byte(this->ha_len);
    pkt_buf->serialize_byte(this->proto_len);
    pkt_buf->serialize_2_bytes(this->op);
    pkt_buf->serialize_mac(this->sender_hwaddr);
    pkt_buf->serialize_4_bytes(this->sender_protocol_addr);
    pkt_buf->serialize_mac(this->target_hwaddr);
    pkt_buf->serialize_4_bytes(this->target_protocol_addr);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status arp_hdr::deserialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    pkt_buf->deserialize_2_bytes(&this->hw_type);
    if (this->hw_type != NETOS_ARP_HWTYPE) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_HW_TYPE,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_2_bytes(&this->protocol_type);
    if (this->protocol_type != NETOS_ETHERTYPE_IPV4) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->ha_len);
    if (this->ha_len != NETOS_ARP_HW_ADDR_LEN) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->proto_len);
    if (this->proto_len != NETOS_ARP_PROTOCOL_ADDR_LEN) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_2_bytes(&this->op);
    if ((this->op != NETOS_ARP_OP_ARP_REQUEST) &&
        (this->op != NETOS_ARP_OP_ARP_REPLY) &&
        (this->op != NETOS_ARP_OP_RARP_REQ) &&
        (this->op != NETOS_ARP_OP_RARP_REPLY) &&
        (this->op != NETOS_ARP_OP_DRARP_REQ) &&
        (this->op != NETOS_ARP_OP_DRARP_REPLY) &&
        (this->op != NETOS_ARP_OP_DRARP_ERROR) &&
        (this->op != NETOS_ARP_OP_INARP_REQ) &&
        (this->op != NETOS_ARP_OP_INARP_REPLY)) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_mac(this->sender_hwaddr);

    if (is_broadcast_mac(this->sender_hwaddr) || is_multicast_mac(this->sender_hwaddr) ||
        is_zero_mac(this->sender_hwaddr)) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_4_bytes(&this->sender_protocol_addr);
    pkt_buf->deserialize_mac(this->target_hwaddr);
    pkt_buf->deserialize_4_bytes(&this->target_protocol_addr);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

