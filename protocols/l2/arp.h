#ifndef PROTOCOLS_L2_ARP_H
#define PROTOCOLS_L2_ARP_H

#include <stdint.h>
#include <time.h>

#include <iostream>
#include <string>
#include <memory>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

#include "netos_macros.h"
#include "packet_buf.h"
#include "hash_table.h"
#include "error_codes.h"
#include "eth.h"
#include "arp_hdr.h"
#include "parsed_pkt.h"

namespace netos {

using namespace netos::lib;

enum class arp_state : uint32_t {
    ARP_STATE_INIT = 1,
    ARP_STATE_RESOLVED,
};

struct arp_entry {
    arp_state   state;
    std::string ifname;
    uint8_t     macaddr[NETOS_MACADDR_LEN];
    uint32_t    ipaddr;
    time_t      last_updated;

    explicit arp_entry() : state(arp_state::ARP_STATE_INIT) { }
    ~arp_entry() { }
};

class arp_cache {
    public:
        explicit arp_cache() { }
        ~arp_cache() { }

        int initialize();
        void deinitialize();
        void update(const std::string &ifname, arp_state state, uint8_t *macaddr, uint32_t ipaddr);
        bool find(uint32_t ipaddr, arp_entry **entry) { return this->arp_cache_.find(ipaddr, entry); }

    private:
        hash_table<uint32_t , arp_entry *> arp_cache_;
};

/**
 * @brief - ARP context class.
 *          Provides the interface to instantiate a ARP context and
 *          provides helpers to send and receive ARP frames.
 */
class arp_context {
    public:
        static arp_context *instance()
        {
            static arp_context ctx;
            return &ctx;
        }

        ~arp_context() { }

        netos_status init();

        void add_rx_frame(parsed_pkt *rx_frame);

    private:
        explicit arp_context() { }
        std::shared_ptr<std::thread> monitor_thr_;
        std::mutex process_thr_lock_;
        std::condition_variable process_cond_lock_;
        arp_cache cache_;
        std::queue<parsed_pkt *> arp_rx_queue_;

        void arp_process_thread();
        void arp_process_packet(parsed_pkt *rx_frame);
        void arp_frame_prepare(parsed_pkt *rx_frame, uint8_t *mac, uint32_t ipaddr);
        void arp_query_timer_handler();
        void arp_cache_mgmt_timer_handler();
        void arp_statistics_inc_buffer_full(const std::string &ifname);
};

}

#endif

