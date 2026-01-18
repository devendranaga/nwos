#include <stdint.h>
#include <arpa/inet.h>
#include "logging.h"
#include "ioctl_nw.h"
#include "arp_hdr.h"
#include "arp.h"
#include "protocol_util.h"
#include "ethertypes.h"
#include "event_mgr.h"

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

static bool arp_macaddr_compare(void *mac1, void *mac2)
{
    uint8_t *mac_1 = (uint8_t *)mac1;
    uint8_t *mac_2 = (uint8_t *)mac2;

    return (memcmp(mac_1, mac_2, NETOS_MACADDR_LEN) == 0);
}

static bool arp_ipaddr_compare(void *ip1, void *ip2)
{
    uint32_t *ip_1 = (uint32_t *)ip1;
    uint32_t *ip_2 = (uint32_t *)ip2;

    printf("ip_1 %x ip_2 %x\n", *ip_1, *ip_2);
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
    arp_cache_ = netos_hash_table_init(100);
}

arp_cache::~arp_cache()
{
    netos_hash_table_free(arp_cache_, nullptr);
}

void arp_cache::update(const std::string &ifname, uint8_t *macaddr)
{
    arp_entry *entry;

    entry = (arp_entry *)calloc(1, sizeof(arp_entry));
    if (!entry) {
        return;
    }

    entry->ifname = ifname;
    memcpy(entry->macaddr, macaddr, NETOS_MACADDR_LEN);
    entry->last_updated = time(0);

    netos_hash_table_add_item(arp_cache_, entry, macaddr, arp_macaddr_hash);
}

void arp_context::add_rx_frame(std::shared_ptr<parsed_pkt> rx_frame)
{
    std::unique_lock<std::mutex> l(this->process_thr_lock_);
    rx_queue_.push(rx_frame);
    this->process_cond_lock_.notify_one();
}

void arp_context::arp_process_packet(std::shared_ptr<parsed_pkt> rx_frame)
{
    uint32_t ipaddr = 0;
    void *res;
    int ret;

    ret = netos_get_ipaddr(rx_frame->ifname.c_str(), &ipaddr);
    if (ret != 0) {
        return;
    }

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
            this->cache_.update(rx_frame->ifname, (uint8_t *)&rx_frame->ah.sender_protocol_addr);
        }
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

