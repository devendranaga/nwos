#include <iostream>
#include <fstream>
#include <string>

#include <jsoncpp/json/json.h>

#include "conversion.h"
#include "pktgen_config.h"
#include "pktgen.h"
#include "logging.h"

namespace netos {

namespace ids {

int pktgen_eth_config::parse(const Json::Value &r)
{
    this->enable = r["enable"].asBool();
    netos::lib::str_to_mac(r["src_mac"].asString(), this->src_mac);
    netos::lib::str_to_mac(r["dst_mac"].asString(), this->dst_mac);
    this->ethertype = std::stoi(r["ethertype"].asString(), nullptr, 16);
    this->randomize = r["randomize"].asBool();
    this->repeat = r["repeat"].asBool();
    this->count = r["count"].asUInt();
    this->pkt_intvl_nsec = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_config::parse(const std::string &config_file)
{
    Json::Value root;
    std::ifstream conf(config_file, std::ifstream::binary);

    conf >> root;

    this->interface = root["interface"].asString();
    this->eth_config.parse(root["eth"]);

    return 0;
}

void pktgen_config::print()
{
    eth_config.print();
}

void pktgen_eth_config::print()
{
    netos_log_info("pktgen: eth_config: {");
    netos_log_info("pktgen: \t enable: %d\n", this->enable);
}

}

}
