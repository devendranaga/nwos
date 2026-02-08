#ifndef NETOS_NETWORKING_EGRESS_QUEUE_H
#define NETOS_NETWORKING_EGRESS_QUEUE_H

#include <stdint.h>
#include <string>
#include <memory>

#include <packet_buf.h>
#include <raw_socket.h>

#define NETWORK_EGRESS_ITEMS_LEN 32

using namespace netos::lib;

namespace netos {

struct network_egress_item {
    std::string ifname;
    packet_buf *pkt_buf;
    std::shared_ptr<raw_socket> raw_fd_;

    network_egress_item() { }
    ~network_egress_item() { }

    void initialize(std::string &ifname, packet_buf *pkt_buf, std::shared_ptr<raw_socket> &raw_fd_);
};

struct network_egress_queue {
    uint32_t priority;
    network_egress_item items[NETWORK_EGRESS_ITEMS_LEN];
};

}

#endif
