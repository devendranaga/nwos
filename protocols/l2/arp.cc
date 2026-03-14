#include <stdint.h>
#include <arpa/inet.h>

#include "signal_intf.h"
#include "logging.h"
#include "ioctl_nw.h"
#include "eth.h"
#include "arp_hdr.h"
#include "arp.h"
#include "protocol_util.h"
#include "ethertypes.h"
#include "event_mgr.h"
#include "statistics.h"
#include "network_egress_intf.h"
#include "network_config.h"
#include "gcd.h"

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

arp_cache::arp_cache()
{
    network_config *config = network_config::instance();

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

void arp_context::add_rx_frame(parsed_pkt *rx_frame)
{
    std::unique_lock<std::mutex> l(this->process_thr_lock_);
    rx_frame->inc_ref_count();
    this->arp_rx_queue_.push(rx_frame);
    this->process_cond_lock_.notify_one();
}

void arp_context::arp_statistics_inc_buffer_full(const std::string &ifname)
{
    statistics *st = statistics::instance();
    stats_intf *intf = st->get_stats_intf(ifname);

    intf->inc_egress_drop_buffer_full();
}

void arp_context::arp_frame_prepare(parsed_pkt *frame,
                                    uint8_t *macaddr,
                                    uint32_t ipaddr)
{
    network_egress_intf intf;
    eth_hdr eh;
    arp_hdr ah;
    std::string ifname = frame->intf_config->ifname;

    intf.ifname = ifname;
    intf.raw_fd_ = frame->raw;
    intf.pkt = packet_buf_pool::instance()->get_pkt();
    if (!intf.pkt) {
        this->arp_statistics_inc_buffer_full(ifname);
        return;
    }

    memcpy(eh.dst_mac, frame->eh.src_mac, NETOS_MACADDR_LEN);
    memcpy(eh.src_mac, macaddr, NETOS_MACADDR_LEN);
    eh.ethertype = NETOS_ETHERTYPE_ARP;
    eh.serialize(intf.pkt);

    ah.arp_reply_defaults(macaddr,
                          frame->eh.src_mac,
                          ntohl(ipaddr),
                          frame->ah.sender_protocol_addr);
    ah.serialize(intf.pkt);

    network_egress::instance()->egress_enque(intf);
}

void arp_context::arp_process_packet(parsed_pkt *rx_frame)
{
    uint8_t mac[6] = {0};
    uint32_t ipaddr = 0;
    void *res;

    // we do not have any ip address
    if (rx_frame->intf_config->ipaddr == 0) {
        parsed_pkt_pool::instance()->put_pkt(rx_frame);
        return;
    }

    ipaddr = rx_frame->intf_config->ipaddr;

    // Packet is directed to us.. do not drop it.
    if ((rx_frame->ah.op == NETOS_ARP_OP_ARP_REQUEST) &&
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
            this->cache_.update(rx_frame->intf_config->ifname,
                            arp_state::ARP_STATE_RESOLVED,
                            rx_frame->ah.sender_hwaddr,
                            rx_frame->ah.sender_protocol_addr);
        }
        this->arp_frame_prepare(rx_frame, mac, ipaddr);
    } else {
        // Drop the frame and cleanup.
    }
}

void arp_context::arp_process_thread()
{
    netos_block_term_signals();

    while (1) {
        std::unique_lock<std::mutex> l(this->process_thr_lock_);
        this->process_cond_lock_.wait(l);
        while (!arp_rx_queue_.empty()) {
            parsed_pkt *rx_frame = arp_rx_queue_.front();

            this->arp_process_packet(rx_frame);
            arp_rx_queue_.pop();
        }
    }
}

void arp_context::arp_query_timer_handler()
{
}

void arp_context::arp_cache_mgmt_timer_handler()
{
}

netos_status arp_context::init()
{
    network_config *config = network_config::instance();
    gcd *gcd_instance = gcd::instance();

    /* Create ARP query timer. */
    std::function<void()> query_timer_cb = std::bind(&arp_context::arp_query_timer_handler, this);

    gcd_instance->register_timer(config->arp_config_.arp_query_timer_intvl_sec,
                                 0,
                                 query_timer_cb);

    /* Create ARP cache management timer. */
    std::function<void()> cache_mgmt_timer_cb = std::bind(&arp_context::arp_cache_mgmt_timer_handler, this);

    gcd_instance->register_timer(config->arp_config_.arp_cache_mgmt_timer_intvl_sec,
                                 0,
                                 cache_mgmt_timer_cb);

    /* Create Receive thread. */
    monitor_thr_ = std::make_shared<std::thread>(&arp_context::arp_process_thread, this);
    monitor_thr_->detach();

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

