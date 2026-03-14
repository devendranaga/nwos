#ifndef NETOS_NETWORKING_MAIN_H
#define NETOS_NETWORKING_MAIN_H

#include <vector>
#include <memory>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "raw_socket.h"
#include "parsed_pkt.h"
#include "network_config.h"
#include "network_interface_config.h"
#include "pcap.h"
#include "perf_linux.h"
#include "network_egress_intf.h"
#include "statistics.h"

using namespace netos::lib;

namespace netos {

/**
 * @brief Network interface class
 * This is per interface class definition and implementation.
 */
class network_interface {
    public:
        explicit network_interface() { }
        std::shared_ptr<raw_socket> get_raw_fd() { return this->raw_; }
        netos_status initialize(const std::string &ifname);

        /**
         * @brief - Gets called upon terminate signal only.
         */
        void raise_signals() {
            std::unique_lock<std::mutex> l(this->rx_pkt_pool_lock_);

            // signal the rest of the threads
            this->parsed_thread_signalled_ = true;
            this->rx_thread_signalled_ = true;

            this->pcap_->terminate();
            this->rx_pkt_pool_cond_.notify_one();
        }

        ~network_interface() { }

    private:
        void rx_thread();
        void parse_thread();
        void dispatch_pkt(parsed_pkt *pkt);

        std::queue<parsed_pkt *> rx_pkt_pool_;
        std::condition_variable rx_pkt_pool_cond_;
        std::mutex rx_pkt_pool_lock_;
        std::shared_ptr<std::thread> rx_thr_;
        std::shared_ptr<std::thread> parse_thr_;
        std::shared_ptr<raw_socket> raw_;
        std::shared_ptr<pcap_mod> pcap_;
        std::shared_ptr<network_interface_config> intf_config_;
        stats_intf *stats_;
        std::shared_ptr<perf_event> latency_event_;
        bool parsed_thread_signalled_;
        bool rx_thread_signalled_;
};

struct network_cmdargs {
    std::string config_file;
};

class network_manager {
    public:
        explicit network_manager() { }
        ~network_manager() {}

        void run(int argc, char **argv);

    private:
        void termination_handler();
        int initialize();
        int parse_cmdargs(int argc, char **argv);
        network_cmdargs cmdargs_;
        std::vector<std::shared_ptr<network_interface>> iflist_;
};

}

#endif

