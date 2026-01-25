#include <stdint.h>
#include <arpa/inet.h>
#include "logging.h"
#include "ioctl_nw.h"
#include "eth.h"
#include "arp_hdr.h"
#include "arp.h"
#include "protocol_util.h"
#include "ethertypes.h"
#include "event_mgr.h"
#include "network_egress_intf.h"
#include "network_config.h"

using namespace netos::ids;

static uint32_t arp_macaddr_hash(void *macaddr_ptr)
{
    uint8_t *macaddr = (uint8_t *)macaddr_ptr;
    uint32_t hash_val = 0;
    uint32_t i;

    for (i = 0; i < NETOS_MACADDR_LEN; i++) {
        hash_val = (hash_val << 4) + macaddr[i];
    }
    return hash_val;
}

static bool arp_ipaddr_compare(void *ip1, void *ip2)
{
    uint32_t *ip_1 = (uint32_t *)ip1;
    uint32_t *ip_2 = (uint32_t *)ip2;

    return (*ip_1 == *ip_2);
}

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

arp_cache::arp_cache()
{
    network_config *config = network_config::instance();

    printf("%d\n", config->arp_config_.arp_table_len);
    arp_cache_ = netos_hash_table_init(config->arp_config_.arp_table_len);
}

arp_cache::~arp_cache()
{
    netos_hash_table_free(arp_cache_, nullptr);
}

void arp_cache::update(const std::string &ifname, arp_state state, uint8_t *macaddr, uint32_t ipaddr)
{
    arp_entry *entry;

    entry = (arp_entry *)calloc(1, sizeof(arp_entry));
    if (!entry) {
        return;
    }

    entry->ifname = ifname;
    entry->state = state;
    memcpy(entry->macaddr, macaddr, NETOS_MACADDR_LEN);
    entry->ipaddr = ipaddr;
    entry->last_updated = time(0);

    netos_hash_table_add_item(arp_cache_, entry, macaddr, arp_macaddr_hash);
}

void arp_context::add_rx_frame(std::shared_ptr<parsed_pkt> rx_frame)
{
    std::unique_lock<std::mutex> l(this->process_thr_lock_);
    rx_queue_.push(rx_frame);
    this->process_cond_lock_.notify_one();
}

void arp_context::arp_frame_prepare(std::shared_ptr<parsed_pkt> frame,
                                    uint8_t *macaddr,
                                    uint32_t ipaddr)
{
    network_egress_intf intf;
    eth_hdr eh;
    arp_hdr ah;

    intf.ifname = frame->ifname;
    intf.raw_fd_ = frame->raw;
    intf.pkt = std::make_shared<packet_buf>();
    intf.pkt->allocate();

    memcpy(eh.dst_mac, frame->eh.src_mac, NETOS_MACADDR_LEN);
    memcpy(eh.src_mac, macaddr, NETOS_MACADDR_LEN);
    eh.ethertype = NETOS_ETHERTYPE_ARP;
    eh.serialize(intf.pkt);

    ah.hw_type = ARP_HW_TYPE_ETHERNET;
    ah.protocol_type = NETOS_ETHERTYPE_IPV4;
    ah.ha_len = ARP_HA_LEN;
    ah.proto_len = ARP_PROTOCOL_LEN;
    memcpy(ah.sender_hwaddr, macaddr, NETOS_MACADDR_LEN);
    ah.sender_protocol_addr = ntohl(ipaddr);
    memcpy(ah.target_hwaddr, frame->eh.src_mac, NETOS_MACADDR_LEN);
    ah.target_protocol_addr = frame->ah.sender_protocol_addr;
    ah.op = ARP_OP_ARP_REPLY;
    ah.serialize(intf.pkt);

    network_egress::instance()->egress_enque(intf);
}

void arp_context::arp_process_packet(std::shared_ptr<parsed_pkt> rx_frame)
{
    uint8_t mac[6] = {0};
    uint32_t ipaddr = 0;
    void *res;
    int ret;

    printf("process packet\n");
    ret = netos_get_macaddr(rx_frame->ifname.c_str(), mac);
    if (ret != 0) {
        return;
    }

    ret = netos_get_ipaddr(rx_frame->ifname.c_str(), &ipaddr);
    if (ret != 0) {
        return;
    }

    printf("op %d\n", rx_frame->ah.op);
    // Packet is directed to us.. do not drop it.
    if ((rx_frame->ah.op == ARP_OP_ARP_REQUEST) &&
        (ntohl(ipaddr) == rx_frame->ah.target_protocol_addr)) {
        res = netos_hash_table_search(this->cache_.get(),
                                      &rx_frame->ah.sender_protocol_addr,
                                      arp_ipaddr_compare,
                                      arp_macaddr_hash);
        if (res) {
            // Update the entry.
            arp_entry *entry = (arp_entry *)res;
            entry->last_updated = time(0);
        } else {
            // Add the entry.
            this->cache_.update(rx_frame->ifname,
                            arp_state::ARP_STATE_RESOLVED,
                            rx_frame->ah.sender_hwaddr,
                            rx_frame->ah.sender_protocol_addr);
        }
        printf("send out egress frame %s\n", rx_frame->ifname.c_str());
        this->arp_frame_prepare(rx_frame, mac, ipaddr);
    } else {
        // Drop the frame and cleanup.
    }
}

void arp_context::arp_process_thread()
{
    while (1) {
        std::unique_lock<std::mutex> l(this->process_thr_lock_);
        this->process_cond_lock_.wait(l);
        while (!rx_queue_.empty()) {
            std::shared_ptr<parsed_pkt> rx_frame = rx_queue_.front();

            this->arp_process_packet(rx_frame);
            rx_queue_.pop();
            l.unlock();
        }
    }
}

netos_status arp_context::init()
{
    rx_thr_ = std::make_shared<std::thread>(&arp_context::arp_process_thread, this);
    rx_thr_->detach();

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

