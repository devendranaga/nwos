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
    this->arp_query_timer_intvl_sec = root["arp_query_timer_intvl_sec"].asUInt();
    this->arp_cache_mgmt_timer_intvl_sec = root["arp_cache_mgmt_timer_intvl_sec"].asUInt();

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

netos_status network_egress_config::parse(Json::Value &root)
{
    this->number_of_queues = root["number_of_queues"].asUInt();
    auto egress_alg = root["egress_algorithm"].asString();
    if (egress_alg == "round_robin") {
        this->algorithm = egress_algorithm::ROUND_ROBIN;
    } else {
        return netos_status::NETOS_STATUS_INVAL_CONFIG;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_ids_config::parse(Json::Value &root)
{
    auto event_fwd_config = root["events"]["event_forwarding"];

    this->event_config.event_fwd_enable =
                        event_fwd_config["enable"].asBool();
    this->event_config.event_fwd_ip =
                        event_fwd_config["server_ip"].asString();
    this->event_config.event_fwd_port =
                        event_fwd_config["server_port"].asUInt();

    auto fwd_protocol = event_fwd_config["server_protocol"].asString();
    if (fwd_protocol == "mqtt") {
        this->event_config.fwd_protocol = event_fwd_protocol::MQTT;
    } else {
        return netos_status::NETOS_STATUS_INVAL_CONFIG;
    }

    this->event_config.timer_period_ms =
                        event_fwd_config["timer_period_ms"].asUInt();

    auto event_storage_config = root["events"]["event_storage"];
    this->event_config.event_storage_enable =
                        event_storage_config["enable"].asBool();
    this->event_config.event_storage_path =
                        event_storage_config["storage_path"].asString();

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_filter_config::parse(Json::Value &root)
{
    this->drop_ipv4_fragments = root["drop_ipv4_fragments"].asBool();
    this->icmp_max_payload_len = root["icmp_max_payload_len"].asUInt();
    this->bypass_ipv4_checksum_verification =
              root["bypass_ipv4_checksum_verification"].asBool();

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_vlan_mapping::parse(Json::Value &root)
{
    this->ifname = root["interface_name"].asString();
    for (auto vlan_id_map : root["vlan_ids"]) {
        network_vlan_id_map vid_map;

        vid_map.ingress_vlan_id =
                        vlan_id_map["ingress_vlan_id"].asUInt();
        vid_map.egress_vlan_id =
                        vlan_id_map["egress_vlan_id"].asUInt();
        this->vlan_id_map.push_back(vid_map);
    }
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_vlan_config::parse(Json::Value &root)
{
    auto vlan_map_config = root["vlan_mapping"];

    for (auto vlan_map : vlan_map_config) {
        network_vlan_mapping vlan_mapping;

        vlan_mapping.parse(vlan_map);
        this->vlan_mapping.push_back(vlan_mapping);
    }

    this->drop_double_tagged_vlan = root["drop_double_tagged_vlan"].asBool();

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status network_cloud_intf_config::parse(Json::Value &root)
{
    auto method = root["method"].asString();
    if (method == "udp") {
        this->method = cloud_intf_method::UDP;
    } else if (method == "mqtt") {
        this->method = cloud_intf_method::MQTT;
    } else if (method == "protobuf") {
        this->method = cloud_intf_method::protobuf;
    } else {
        return netos_status::NETOS_STATUS_INVAL_CONFIG;
    }

    this->server_ip = root["server_ip"].asString();
    this->server_port = root["server_port"].asUInt();

    this->stats_tx_interval_sec = root["stats_tx_interval_sec"].asUInt();

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
    auto vlan_config = root["network_config"]["vlan_config"];
    this->vlan_config_.parse(vlan_config);

    auto arp_config = root["network_config"]["arp_config"];
    this->arp_config_.parse(arp_config);

    this->packet_buf_pool_len = root["network_config"]["packet_buf_pool_len"].asUInt();
    this->parsed_pkt_buf_pool_len = root["network_config"]["parsed_pkt_buf_pool_len"].asUInt();

    auto log_config = root["network_config"]["logging"];
    this->log_config_.parse(log_config);

    auto filter_config = root["network_config"]["filter"];
    this->filter_config_.parse(filter_config);

    auto egress_config = root["network_config"]["egress"];
    this->egress_config_.parse(egress_config);

    auto ids_config = root["network_config"]["ids"];
    this->ids_config_.parse(ids_config);

    auto cloud_intf_config = root["network_config"]["cloud_interface"];
    this->cloud_config_.parse(cloud_intf_config);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

