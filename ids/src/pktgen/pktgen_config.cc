#include <netinet/in.h>
#include <arpa/inet.h>

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

int pktgen_arp_config::parse(const Json::Value &r)
{
    this->enable = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    this->hw_type = r["hw_type"].asUInt();
    auto p_str = r["protocol"].asString();
    netos::lib::str_hex_to_int(p_str, &this->protocol);
    this->ha_len = r["ha_len"].asUInt();
    this->protocol_addr_len = r["protocol_addr_len"].asUInt();
    this->arp_op = r["op"].asUInt();
    netos::lib::str_to_mac(r["sender_hwaddr"].asString(), this->sender_hwaddr);
    auto s_p_addr_str = r["sender_protocol_addr"].asString();
    this->sender_protocol_addr = inet_addr(s_p_addr_str.c_str());
    netos::lib::str_to_mac(r["target_hwaddr"].asString(), this->target_hwaddr);
    auto t_p_addr_str = r["target_protocol_addr"].asString();
    this->target_protocol_addr = inet_addr(t_p_addr_str.c_str());
    this->randomize = r["randomize"].asBool();
    this->repeat = r["repeat"].asBool();
    this->count = r["count"].asUInt();
    this->pkt_intvl_nsec = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_vlan_config::parse(const Json::Value &r)
{
    this->enable = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    this->randomize = r["randomize"].asBool();
    for (auto it : r["multi_vlan_tag"]) {
        this->vlan_ids.push_back(it["vid"].asUInt());
    }
    this->repeat = r["repeat"].asBool();
    this->pkt_intvl_nsec = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_ipv4_config::parse(const Json::Value &r)
{
    this->enable = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    this->vlan_enable = r["vlan"]["enable"].asBool();
    for (auto it : r["vlan"]["multi_vlan_tag"]) {
        this->vlan_ids.push_back(it["vid"].asUInt());
    }
    this->version = r["version"].asUInt();
    this->ihl = r["ihl"].asUInt();
    this->dscp = r["dscp"].asUInt();
    this->ecn = r["ecn"].asUInt();
    this->total_len = r["total_len"].asUInt();
    auto str = r["id"].asString();
    netos::lib::str_hex_to_int(str, &this->id);
    this->reserved = r["flags"]["reserved"].asUInt();
    this->df = r["flags"]["df"].asUInt();
    this->mf = r["flags"]["mf"].asUInt();
    this->frag_off = r["frag_off"].asUInt();
    this->ttl = r["ttl"].asUInt();
    this->protocol = r["protocol"].asUInt();
    this->hdr_checksum_autogen = r["hdr_chksum_autogen"].asBool();
    auto hdr_chksum_str = r["hdr_chksum"].asString();
    netos::lib::str_hex_to_int(hdr_chksum_str, &this->hdr_checksum);
    auto s_addr_str = r["src_addr"].asString();
    this->src_addr = inet_addr(s_addr_str.c_str());
    auto d_addr_str = r["dst_addr"].asString();
    this->dst_addr = inet_addr(d_addr_str.c_str());
    this->repeat = r["repeat"].asBool();
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
    this->arp_config.parse(root["arp"]);
    this->vlan_config.parse(root["vlan"]);
    this->ipv4_config.parse(root["ipv4"]);

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
