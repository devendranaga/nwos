#ifndef NETOS_NETWORKING_EGRESS_QUEUE_H
#define NETOS_NETWORKING_EGRESS_QUEUE_H

#include <stdint.h>
#include <string>
#include <memory>
#include <mutex>

#include <packet_buf.h>
#include <raw_socket.h>

#define NETWORK_EGRESS_ITEMS_LEN 32

using namespace netos::lib;

namespace netos {

/**
 * @brief - Defines an Egress item.
 */
struct network_egress_item {
    bool available;
    std::string ifname;
    packet_buf *pkt_buf;
    std::shared_ptr<raw_socket> raw_fd;

    network_egress_item() { }
    ~network_egress_item() { }
};

struct network_egress_queue {
    uint32_t priority;
    network_egress_item *items;
    std::mutex lock;
};

}

#endif
