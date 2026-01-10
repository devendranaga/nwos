#include <iostream>
#include <fstream>
#include <string>

#include <jsoncpp/json/json.h>

#include "network_config.h"

using namespace netos::lib;

namespace netos {

netos_status network_if_config::parse(Json::Value &root)
{
    this->ifname = root["interface_name"].asString();

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_config::parse(const std::string &config)
{
    netos_status ret;
    Json::Value root;
    std::ifstream conf(config, std::ifstream::binary);

    conf >> root;

    auto netw_configs = root["network_config"];
    for (auto config : netw_configs) {
        network_if_config net_if_config;

        ret = net_if_config.parse(config);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return ret;
        }
        this->if_config_list_.push_back(net_if_config);
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

