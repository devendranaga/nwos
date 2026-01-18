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

#include "ids_macro_defs.h"
#include "packet_buf.h"
#include "hash_table.h"
#include "error_codes.h"
#include "eth.h"
#include "arp_hdr.h"
#include "parsed_pkt.h"

#define NETOS_ARP_HWTYPE                1
#define NETOS_ARP_HW_ADDR_LEN           6
#define NETOS_ARP_PROTOCOL_ADDR_LEN     4

#define NETOS_ARP_OP_ARP_REQUEST        1
#define NETOS_ARP_OP_ARP_REPLY          2
#define NETOS_ARP_OP_RARP_REQ           3
#define NETOS_ARP_OP_RARP_REPLY         4
#define NETOS_ARP_OP_DRARP_REQ          5
#define NETOS_ARP_OP_DRARP_REPLY        6
#define NETOS_ARP_OP_DRARP_ERROR        7
#define NETOS_ARP_OP_INARP_REQ          8
#define NETOS_ARP_OP_INARP_REPLY        9

namespace netos {

enum class arp_state : uint32_t {
    ARP_STATE_INIT = 1,
    ARP_STATE_RESOLVED,
};

struct arp_entry {
    arp_state state;
    std::string ifname;
    uint8_t macaddr[NETOS_MACADDR_LEN];
    time_t last_updated;

    explicit arp_entry() : state(arp_state::ARP_STATE_INIT) { }
    ~arp_entry() { }
};

class arp_cache {
    public:
        explicit arp_cache();
        ~arp_cache();

        void update(const std::string &ifname, uint8_t *macaddr);
        netos_hash_table *get() { return arp_cache_; }

    private:
        netos_hash_table *arp_cache_;
};

class arp_context {
    public:
        static arp_context *instance()
        {
            static arp_context ctx;
            return &ctx;
        }

        ~arp_context() { }

        netos_status init();

        void add_rx_frame(std::shared_ptr<parsed_pkt> rx_frame);

    private:
        explicit arp_context() { }
        std::shared_ptr<std::thread> rx_thr_;
        std::mutex process_thr_lock_;
        std::condition_variable process_cond_lock_;
        arp_cache cache_;
        std::queue<std::shared_ptr<parsed_pkt>> rx_queue_;

        void arp_process_thread();
        void arp_process_packet(std::shared_ptr<parsed_pkt> rx_frame);
        void arp_frame_prepare(std::shared_ptr<parsed_pkt> rx_frame, uint8_t *mac, uint32_t ipaddr);
};

}

#endif

