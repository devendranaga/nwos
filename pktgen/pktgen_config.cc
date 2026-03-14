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

int pktgen_eth_config::parse(const Json::Value &r)
{
    this->enable         = r["enable"].asBool();
    netos::lib::str_to_mac(r["src_mac"].asString(), this->src_mac);
    netos::lib::str_to_mac(r["dst_mac"].asString(), this->dst_mac);
    this->ethertype      = std::stoi(r["ethertype"].asString(), nullptr, 16);
    this->randomize      = r["randomize"].asBool();
    this->repeat         = r["repeat"].asBool();
    this->count          = r["count"].asUInt();
    this->pkt_intvl_nsec = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_macsec_config::parse(const Json::Value &r)
{
    this->enable            = r["enable"].asBool();

    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    this->tci.version       = r["tci"]["version"].asUInt();
    this->tci.es            = r["tci"]["es"].asUInt();
    this->tci.sc            = r["tci"]["sc"].asUInt();
    this->tci.scb           = r["tci"]["scb"].asUInt();
    this->tci.e             = r["tci"]["e"].asUInt();
    this->tci.c             = r["tci"]["c"].asUInt();
    this->tci.an            = r["tci"]["an"].asUInt();

    this->short_len         = r["short_len"].asUInt();
    this->pn                = r["pn"].asUInt();
    this->macsec_ethertype  = std::stoi(r["macsec_ethertype"].asString(), nullptr, 16);
    netos::lib::str_to_mac(r["sci"]["mac"].asString(), this->sci_mac);
    this->sci_port_id       = r["sci"]["port_id"].asUInt();

    auto icv_array          = r["icv"];
    uint32_t i = 0;

    for (auto icv_byte : icv_array) {
        this->icv[i] = icv_byte.asUInt();
        i ++;
    }

    this->randomize         = r["randomize"].asBool();
    this->repeat            = r["repeat"].asBool();
    this->count             = r["count"].asUInt();
    this->pkt_intvl_nsec    = r["pkt_intvl_nsec"].asUInt();

    return 0;
}

int pktgen_arp_config::parse(const Json::Value &r)
{
    this->enable                = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    for (auto it : r["multi_vlan_tag"]) {
        this->vlan_ids.push_back(it["vid"].asUInt());
    }
    this->hw_type               = r["hw_type"].asUInt();
    auto p_str                  = r["protocol"].asString();
    netos::lib::str_hex_to_int(p_str, &this->protocol);
    this->ha_len                = r["ha_len"].asUInt();
    this->protocol_addr_len     = r["protocol_addr_len"].asUInt();
    this->arp_op                = r["op"].asUInt();
    netos::lib::str_to_mac(r["sender_hwaddr"].asString(), this->sender_hwaddr);
    auto s_p_addr_str           = r["sender_protocol_addr"].asString();
    netos::lib::ipaddr_str_to_uint(s_p_addr_str, &this->sender_protocol_addr);
    netos::lib::str_to_mac(r["target_hwaddr"].asString(), this->target_hwaddr);
    auto t_p_addr_str           = r["target_protocol_addr"].asString();
    netos::lib::ipaddr_str_to_uint(t_p_addr_str, &this->target_protocol_addr);
    this->randomize             = r["randomize"].asBool();
    this->repeat                = r["repeat"].asBool();
    this->count                 = r["count"].asUInt();
    this->pkt_intvl_nsec        = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_vlan_config::parse(const Json::Value &r)
{
    this->enable                = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    this->ethertype             = std::stoi(r["eth"]["ethertype"].asString(), nullptr, 16);
    this->randomize             = r["randomize"].asBool();
    for (auto it : r["multi_vlan_tag"]) {
        this->vlan_ids.push_back(it["vid"].asUInt());
    }
    this->repeat                = r["repeat"].asBool();
    this->count                 = r["count"].asUInt();
    this->pkt_intvl_nsec        = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_ipv4_config::parse(const Json::Value &r)
{
    this->enable                = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    this->vlan_enable           = r["vlan"]["enable"].asBool();
    for (auto it : r["vlan"]["multi_vlan_tag"]) {
        this->vlan_ids.push_back(it["vid"].asUInt());
    }
    this->version               = r["version"].asUInt();
    this->ihl                   = r["ihl"].asUInt();
    this->dscp                  = r["dscp"].asUInt();
    this->ecn                   = r["ecn"].asUInt();
    this->total_len             = r["total_len"].asUInt();
    auto str                    = r["id"].asString();
    netos::lib::str_hex_to_int(str, &this->id);
    this->reserved              = r["flags"]["reserved"].asUInt();
    this->df                    = r["flags"]["df"].asUInt();
    this->mf                    = r["flags"]["mf"].asUInt();
    this->frag_off              = r["frag_off"].asUInt();
    this->ttl                   = r["ttl"].asUInt();
    this->protocol              = r["protocol"].asUInt();
    this->hdr_checksum_autogen  = r["hdr_chksum_autogen"].asBool();
    auto hdr_chksum_str         = r["hdr_chksum"].asString();
    netos::lib::str_hex_to_int(hdr_chksum_str, &this->hdr_checksum);
    auto s_addr_str             = r["src_addr"].asString();
    netos::lib::ipaddr_str_to_uint(s_addr_str, &this->src_addr);
    auto d_addr_str             = r["dst_addr"].asString();
    netos::lib::ipaddr_str_to_uint(d_addr_str, &this->dst_addr);
    this->repeat                = r["repeat"].asBool();
    this->count                 = r["count"].asUInt();
    this->pkt_intvl_nsec        = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_ipv6_config::parse(const Json::Value &r)
{
    this->enable                = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    this->vlan_enable           = r["vlan"]["enable"].asBool();
    for (auto it : r["vlan"]["multi_vlan_tag"]) {
        this->vlan_ids.push_back(it["vid"].asUInt());
    }
    this->version               = r["version"].asUInt();
    this->traffic_class         = r["traffic_class"].asUInt();
    this->flow_label            = r["flow_label"].asUInt();
    this->payload_len           = r["payload_len"].asUInt();
    this->nh                    = r["nh"].asUInt();
    this->hop_limit             = r["hop_limit"].asUInt();

    struct in6_addr s_addr;
    auto s_addr_str             = r["src_addr"].asString();
    auto ret = inet_pton(AF_INET6, s_addr_str.c_str(), &s_addr);
    if (ret == 1) {
        memcpy(this->src_addr, s_addr.s6_addr, NETOS_IPV6_ADDR_LEN);
    }

    struct in6_addr d_addr;
    auto d_addr_str             = r["dst_addr"].asString();
    ret = inet_pton(AF_INET6, d_addr_str.c_str(), &d_addr);
    if (ret == 1) {
        memcpy(this->dst_addr, d_addr.s6_addr, NETOS_IPV6_ADDR_LEN);
    }

    this->randomize             = r["randomize"].asBool();
    this->repeat                = r["repeat"].asBool();
    this->count                 = r["count"].asUInt();
    this->pkt_intvl_nsec        = r["pkt_intvl_nsec"].asUInt64();

    return 0;
}

int pktgen_icmp_config::parse(const Json::Value &r)
{
    this->enable                = r["enable"].asBool();
    netos::lib::str_to_mac(r["eth"]["src_mac"].asString(), this->eth_src_mac);
    netos::lib::str_to_mac(r["eth"]["dst_mac"].asString(), this->eth_dst_mac);
    auto s_addr_str             = r["ipv4"]["src_addr"].asString();
    netos::lib::ipaddr_str_to_uint(s_addr_str, &this->src_addr);
    auto d_addr_str             = r["ipv4"]["dst_addr"].asString();
    netos::lib::ipaddr_str_to_uint(d_addr_str, &this->dst_addr);
    this->type                  = r["type"].asUInt();
    this->code                  = r["code"].asUInt();
    auto id_str                 = r["identifier"].asString();
    netos::lib::str_hex_to_int(id_str, &this->identifier);
    auto seq_str                = r["sequence_number"].asString();
    netos::lib::str_hex_to_int(seq_str, &this->sequence_number);
    this->randomize             = r["randomize"].asBool();
    this->repeat                = r["repeat"].asBool();
    this->count                 = r["count"].asUInt();
    this->pkt_intvl_nsec        = r["pkt_intvl_nsec"].asUInt64();
    this->payload_len           = r["payload_len"].asUInt();

    return 0;
}

int pktgen_config::parse(const std::string &config_file)
{
    Json::Value root;
    std::ifstream conf(config_file, std::ifstream::binary);

    conf >> root;

    this->interface = root["interface"].asString();
    this->eth_config.parse(root["eth"]);
    this->macsec_config.parse(root["macsec"]);
    this->arp_config.parse(root["arp"]);
    this->vlan_config.parse(root["vlan"]);
    this->ipv4_config.parse(root["ipv4"]);
    this->ipv6_config.parse(root["ipv6"]);
    this->icmp_config.parse(root["icmp"]);

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
