#ifndef NETOS_NETWORK_CONFIG_H
#define NETOS_NETWORK_CONFIG_H

#include <vector>
#include <jsoncpp/json/json.h>

#include "error_codes.h"

using namespace netos::lib;

namespace netos {

struct network_arp_config {
    uint32_t arp_table_len;

    netos_status parse(Json::Value &root);
};

struct network_if_config {
    std::string ifname;

    netos_status parse(Json::Value &root);
};

struct network_log_config {
    std::string debug_log_server_ip;
    uint16_t debug_log_server_port;

    netos_status parse(Json::Value &root);
};

struct network_config {
    public:
        network_if_config if_config_;
        network_arp_config arp_config_;
        network_log_config log_config_;

        ~network_config() { }
        static network_config *instance() {
            static network_config netw_config;
            return &netw_config;
        }

        netos_status parse(const std::string &config);
    private:
        explicit network_config() { }
};

}

#endif

