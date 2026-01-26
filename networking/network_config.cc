#include <iostream>
#include <fstream>
#include <string>

#include <jsoncpp/json/json.h>

#include "network_config.h"

using namespace netos::lib;

namespace netos {

netos_status network_if_config::parse(Json::Value &root)
{
    for (auto ifname_ptr : root["interface_list"]) {
        this->ifname.push_back(ifname_ptr.asString());
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_arp_config::parse(Json::Value &root)
{
    this->arp_table_len = root["arp_table_len"].asUInt();

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_log_config::parse(Json::Value &root)
{
    this->debug_log_server_ip = root["debug_log_server_ip"].asString();
    this->debug_log_server_port = root["debug_log_server_port"].asUInt();
    this->log_pcap = root["log_pcap"].asBool();
    this->pcap_file_path = root["pcap_file_path"].asString();

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

    auto log_config = root["network_config"]["logging"];
    this->log_config_.parse(log_config);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

