#include <stdint.h>
#include <arpa/inet.h>
#include <functional>

#include "hash_table.h"
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

namespace netos {

using namespace netos::lib;

uint32_t arp_cache_hash_fn(uint32_t ipaddr)
{
    return ((ipaddr & 0xFF000000) >> 24) +
           ((ipaddr & 0x00FF0000) >> 16) +
           ((ipaddr & 0x0000FF00) >> 8) +
           ipaddr & 0x000000FF;
}

bool arp_cache_find_fn(uint32_t ipaddr1, uint32_t ipaddr2)
{
    return ipaddr1 == ipaddr2;
}

bool arp_cache_delete_fn(uint32_t ipaddr, arp_entry *entry)
{
    free(entry);
    return true;
}

int arp_cache::initialize()
{
    network_config *config = network_config::instance();
    for_each_fn<uint32_t, arp_entry *>  fe_fn =
                        std::bind(&arp_cache::for_each_arp_entry_cb,
                                  this,
                                  std::placeholders::_1,
                                  std::placeholders::_2);

    return this->arp_cache_.initialize(config->arp_config_.arp_table_len,
                                       arp_cache_hash_fn,
                                       arp_cache_find_fn,
                                       arp_cache_delete_fn,
                                       fe_fn);
}

bool arp_cache::for_each_arp_entry_cb(uint32_t ipaddr, arp_entry *entry)
{
    network_config *config = network_config::instance();
    time_t now = time(0);

    /* Set state to ARP_REQUESTED. */
    if ((config->arp_config_.arp_cache_mgmt_timer_intvl_sec <=
                        (now - entry->last_updated)) &&
        (entry->tx_count < config->arp_config_.arp_retry_count)) {

        entry->state = arp_state::ARP_STATE_QUERY_REQUESTED;
        this->arp_req_prepare(entry);
        entry->tx_count ++;
    }

    if (entry->state == arp_state::ARP_STATE_QUERY_REQUESTED) {
        if (entry->tx_count >= config->arp_config_.arp_retry_count) {
            this->arp_cache_.remove(ipaddr);
            return true;
        }
    }

    return false;
}

void arp_cache::deinitialize()
{
    arp_cache_.deinitialize();
}

void arp_cache::update(std::shared_ptr<network_interface_config> &intf_config,
                       arp_state state,
                       uint8_t *macaddr,
                       uint32_t ipaddr)
{
    arp_entry *entry;

    entry = (arp_entry *)calloc(1, sizeof(arp_entry));
    if (!entry) {
        return;
    }

    entry->intf_config  = intf_config;
    entry->state        = state;
    memcpy(entry->macaddr, macaddr, NETOS_MACADDR_LEN);
    entry->ipaddr       = ipaddr;
    entry->last_updated = time(0);
    entry->tx_count     = 0;

    this->arp_cache_.add(ipaddr, entry);
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

void arp_context::arp_reply_prepare(parsed_pkt *frame,
                                    uint8_t *macaddr,
                                    uint32_t ipaddr)
{
    network_egress_intf intf;
    eth_hdr eh(frame->eh.src_mac, macaddr, NETOS_ETHERTYPE_ARP);
    arp_hdr ah;
    std::string ifname = frame->intf_config->ifname;

    intf.ifname = ifname;
    intf.raw_fd_ = frame->raw;
    intf.pkt = packet_buf_pool::instance()->get_pkt();
    if (!intf.pkt) {
        this->arp_statistics_inc_buffer_full(ifname);
        return;
    }

    eh.serialize(intf.pkt);

    ah.arp_reply_defaults(macaddr,
                          frame->eh.src_mac,
                          ntohl(ipaddr),
                          frame->ah.sender_protocol_addr);
    ah.serialize(intf.pkt);

    network_egress::instance()->egress_enque(intf);
}

void arp_cache::arp_req_prepare(arp_entry *entry)
{
    network_egress_intf intf;
    eth_hdr eh(entry->macaddr, entry->intf_config->mac, NETOS_ETHERTYPE_ARP);
    arp_hdr ah;
    std::string ifname = entry->intf_config->ifname;

    intf.ifname     = ifname;
    intf.raw_fd_    = entry->intf_config->raw;
    intf.pkt = packet_buf_pool::instance()->get_pkt();
    if (!intf.pkt) {
        return;
    }

    eh.serialize(intf.pkt);

    ah.arp_request_defaults(entry->intf_config->mac,
                            entry->macaddr,
                            ntohl(entry->intf_config->ipaddr),
                            entry->ipaddr);
    ah.serialize(intf.pkt);

    network_egress::instance()->egress_enque(intf);
}

void arp_context::arp_process_packet(parsed_pkt *rx_frame)
{
    uint32_t ipaddr = 0;

    // we do not have any ip address
    if (rx_frame->intf_config->ipaddr == 0) {
        parsed_pkt_pool::instance()->put_pkt(rx_frame);
        return;
    }

    ipaddr = rx_frame->intf_config->ipaddr;

    // Packet is directed to us.. do not drop it.
    if ((rx_frame->ah.op == NETOS_ARP_OP_ARP_REQUEST) &&
        (ntohl(ipaddr) == rx_frame->ah.target_protocol_addr)) {
        struct arp_entry *entry = nullptr;
        bool res;

        res = this->cache_.find(rx_frame->ah.sender_protocol_addr, &entry);
        if (res) {
            // Update the entry.
            entry->last_updated = time(0);
        } else {
            // Add the entry.
            this->cache_.update(rx_frame->intf_config,
                                arp_state::ARP_STATE_RESOLVED,
                                rx_frame->ah.sender_hwaddr,
                                rx_frame->ah.sender_protocol_addr);
        }
        this->arp_reply_prepare(rx_frame, rx_frame->intf_config->mac, ipaddr);
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
    this->cache_.for_each();
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

    /* Create Receive thread. */
    monitor_thr_ = std::make_shared<std::thread>(&arp_context::arp_process_thread, this);
    monitor_thr_->detach();
    cache_.initialize();

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

