#ifndef NETWORKING_NETWORK_EGRESS_INTF_H
#define NETWORKING_NETWORK_EGRESS_INTF_H

#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <memory>
#include <condition_variable>

#include "egress_queue.h"
#include "raw_socket.h"
#include "logging.h"

#define NETWORK_EGRESS_QUEUES_LEN 8

using namespace netos::lib;

namespace netos {

struct network_egress_intf {
    std::string ifname;
    packet_buf *pkt;
    std::shared_ptr<raw_socket> raw_fd_;

    explicit network_egress_intf() : ifname(""),
                                     pkt(nullptr),
                                     raw_fd_(nullptr) {}
    ~network_egress_intf() {}
};

struct network_egress_interface_ctx {
    std::queue<network_egress_intf> egress_queue_;
    network_egress_queue *queues_;
    std::condition_variable egress_queue_cond_;
    std::shared_ptr<std::thread> egress_thr_;
    std::shared_ptr<raw_socket> raw_fd_;
    std::mutex egress_queue_lock_;
    std::string ifname_;

    explicit network_egress_interface_ctx() : raw_fd_(nullptr),
                                              ifname_("") {}
    ~network_egress_interface_ctx() {}

    void initialize();

    private:
        void egress_tx_thread();
};

class network_egress {
    public:
        ~network_egress() {}
        static network_egress *instance()
        {
            static network_egress egress;
            return &egress;
        }

        void add_interface_ctx(std::shared_ptr<raw_socket> raw,
                               std::string ifname);
        void egress_enque(network_egress_intf &intf);

    private:
        std::vector<std::shared_ptr<network_egress_interface_ctx>> interface_ctx_list_;

        explicit network_egress() {}
};

}

#endif
