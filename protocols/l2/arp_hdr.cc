#include <stdint.h>
#include <string.h>

#include "logging.h"
#include "protocol_util.h"
#include "event_info.h"
#include "event_mgr.h"
#include "packet_buf.h"
#include "arp_hdr.h"

namespace netos {

netos_status arp_hdr::serialize(packet_buf *pkt_buf)
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

netos_status arp_hdr::deserialize(packet_buf *pkt_buf)
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
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_PROTO_TYPE,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->ha_len);
    if (this->ha_len != NETOS_ARP_HW_ADDR_LEN) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_HW_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->proto_len);
    if (this->proto_len != NETOS_ARP_PROTOCOL_ADDR_LEN) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_PROTO_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
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
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_OP,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_mac(this->sender_hwaddr);

    if (is_broadcast_mac(this->sender_hwaddr) || is_multicast_mac(this->sender_hwaddr) ||
        is_zero_mac(this->sender_hwaddr)) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_SENDER_HWADDR,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_4_bytes(&this->sender_protocol_addr);
    if (is_zero_ipaddr(this->sender_protocol_addr) ||
        is_broadcast_ipaddr(this->sender_protocol_addr) ||
        is_multicast_ipaddr(this->sender_protocol_addr)) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_SENDER_PROTO_ADDR,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_mac(this->target_hwaddr);
    pkt_buf->deserialize_4_bytes(&this->target_protocol_addr);
    if (is_broadcast_ipaddr(this->target_protocol_addr) ||
        is_multicast_ipaddr(this->target_protocol_addr)) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_ARP_TARGET_PROTO_ADDR,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ARP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->print();
    return netos_status::NETOS_STATUS_SUCCESS;
}

#if defined(NETOS_DEBUG_PKT_DECODE)
void arp_hdr::print()
{
    netos_log_info("arp_hdr:\n");
    netos_log_info("\t hw_type: %d\n", this->hw_type);
    netos_log_info("\t protocol_type: 0x%04x\n", this->protocol_type);
    netos_log_info("\t ha_len: %d\n", this->ha_len);
    netos_log_info("\t proto_len: %d\n", this->proto_len);
    netos_log_info("\t op: %d\n", this->op);
    netos_log_info("\t sender_hwaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            this->sender_hwaddr[0], this->sender_hwaddr[1],
                            this->sender_hwaddr[2], this->sender_hwaddr[3],
                            this->sender_hwaddr[4], this->sender_hwaddr[5]);
    netos_log_info("\t sender_protocol_addr: 0x%x\n", this->sender_protocol_addr);
    netos_log_info("\t target_hwaddr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            this->target_hwaddr[0], this->target_hwaddr[1],
                            this->target_hwaddr[2], this->target_hwaddr[3],
                            this->target_hwaddr[4], this->target_hwaddr[5]);
    netos_log_info("\t target_protocol_addr: 0x%x\n", this->target_protocol_addr);
}
#else
void arp_hdr::print() { }
#endif

}

