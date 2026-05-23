#ifndef NETOS_NETWORK_INTERFACE_CONFIG_H
#define NETOS_NETWORK_INTERFACE_CONFIG_H

#include <raw_socket.h>

namespace netos {

using namespace lib;

struct network_interface_config {
    std::string                 ifname;
    uint8_t                     mac[NETOS_MACADDR_LEN];
    uint32_t                    ipaddr;
    std::shared_ptr<raw_socket> raw;

    explicit network_interface_config() { }
    ~network_interface_config() { }

    void initialize(const std::string &ifname,
                    std::shared_ptr<raw_socket> raw);
};

}

#endif
