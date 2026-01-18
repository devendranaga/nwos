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
#include "network_egress_intf.h"

using namespace netos::lib;

namespace netos {

class network_interface {
    public:
        explicit network_interface() { }
        netos_status initialize(network_if_config &if_config);

        ~network_interface() { }

    private:
        void tx_thread();
        void rx_thread();
        void parse_thread();
        void dispatch_pkt(std::shared_ptr<parsed_pkt> pkt);

        std::queue<std::shared_ptr<parsed_pkt>> rx_pkt_pool_;
        std::condition_variable rx_pkt_pool_cond_;
        std::mutex rx_pkt_pool_lock_;
        std::shared_ptr<std::thread> tx_thr_;
        std::shared_ptr<std::thread> rx_thr_;
        std::shared_ptr<std::thread> parse_thr_;
        std::string ifname_;
        std::shared_ptr<raw_socket> raw_;
};

struct network_cmdargs {
    std::string config_file;
};

class network_manager {
    public:
        void run(int argc, char **argv);

    private:
        int initialize();
        int parse_cmdargs(int argc, char **argv);
        network_cmdargs cmdargs_;
        std::vector<std::shared_ptr<network_interface>> iflist_;
};

}

#endif

