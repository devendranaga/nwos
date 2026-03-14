#ifndef NETOS_NETWORK_INTERFACE_CONFIG_H
#define NETOS_NETWORK_INTERFACE_CONFIG_H

namespace netos {

struct network_interface_config {
    std::string         ifname;
    uint8_t             mac[NETOS_MACADDR_LEN];
    uint32_t            ipaddr;

    explicit network_interface_config() { }
    ~network_interface_config() { }

    void initialize(const std::string &ifname);
};

}

#endif
