#ifndef NETWORKING_NETWORK_EGRESS_INTF_H
#define NETWORKING_NETWORK_EGRESS_INTF_H

#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <memory>
#include <condition_variable>

#include "packet_buf.h"
#include "raw_socket.h"

namespace netos {

struct network_egress_intf {
    std::string ifname;
    std::shared_ptr<packet_buf> pkt;
    std::shared_ptr<raw_socket> raw_fd_;
};

class network_egress {
    public:
        ~network_egress() {}
        static network_egress *instance()
        {
            static network_egress egress;
            return &egress;
        }

        void egress_enque(network_egress_intf &intf);

    private:
        std::queue<network_egress_intf> egress_queue_;
        std::shared_ptr<std::thread> egress_thr_;
        std::mutex egress_queue_lock_;
        std::condition_variable egress_queue_cond_;

        explicit network_egress() {}
        void egres_thread();
};

}

#endif
