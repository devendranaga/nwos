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

netos_status network_arp_config::parse(Json::Value &root)
{
    this->arp_table_len = root["arp_table_len"].asUInt();

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_config::parse(const std::string &config)
{
    netos_status ret;
    Json::Value root;
    std::ifstream conf(config, std::ifstream::binary);

    conf >> root;

    ret = this->if_config_.parse(root["network_config"]);
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }
    auto arp_config = root["network_config"]["arp_config"];
    this->arp_config_.parse(arp_config);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

