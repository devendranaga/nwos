#include <iostream>
#include <fstream>
#include <string>

#include <jsoncpp/json/json.h>

#include "logging.h"
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

void network_if_config::print()
{
    netos_log_verbose("Interface Configuration:\n");
    for (auto ifname : this->ifname) {
        netos_log_verbose("\t %s\n", ifname.c_str());
    }
}

netos_status network_arp_config::parse(Json::Value &root)
{
    this->arp_table_len                     = root["arp_table_len"].asUInt();
    this->arp_query_timer_intvl_sec         = root["arp_query_timer_intvl_sec"].asUInt();
    this->arp_cache_mgmt_timer_intvl_sec    = root["arp_cache_mgmt_timer_intvl_sec"].asUInt();
    this->arp_retry_count                   = root["arp_retry_count"].asUInt();

    return netos_status::NETOS_STATUS_SUCCESS;
}

void network_arp_config::print()
{
    netos_log_verbose("ARP Configuration:\n");
    netos_log_verbose("\t ARP Table Length: %u\n", this->arp_table_len);
    netos_log_verbose("\t ARP Query Timer Interval (sec): %u\n",
                      this->arp_query_timer_intvl_sec);
    netos_log_verbose("\t ARP Cache Management Timer Interval (sec): %u\n",
                      this->arp_cache_mgmt_timer_intvl_sec);
    netos_log_verbose("\t ARP Retry Count: %d\n",
                      this->arp_retry_count);
}

netos_status network_log_config::parse(Json::Value &root)
{
    this->debug_log_server_ip = root["debug_log_server_ip"].asString();
    this->debug_log_server_port = root["debug_log_server_port"].asUInt();
    this->log_pcap = root["log_pcap"].asBool();
    this->pcap_file_path = root["pcap_file_path"].asString();

    return netos_status::NETOS_STATUS_SUCCESS;
}

void network_log_config::print()
{
    netos_log_verbose("Logging Configuration:\n");
    netos_log_verbose("\t Debug Log Server IP: %s\n", this->debug_log_server_ip.c_str());
    netos_log_verbose("\t Debug Log Server Port: %u\n", this->debug_log_server_port);
    netos_log_verbose("\t Log PCAP: %s\n", this->log_pcap ? "true" : "false");
    netos_log_verbose("\t PCAP File Path: %s\n", this->pcap_file_path.c_str());
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

void network_egress_config::print()
{
    netos_log_verbose("Egress Configuration:\n");
    netos_log_verbose("\t Number of Egress Queues: %u\n", this->number_of_queues);
    netos_log_verbose("\t Egress Algorithm: %s\n", this->algorithm_str().c_str());
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
    this->event_config.event_storage_file_prefix =
                        event_storage_config["log_storage_prefix"].asString();

    return netos_status::NETOS_STATUS_SUCCESS;
}

void network_ids_config::print()
{
    netos_log_verbose("IDS Configuration:\n");
    netos_log_verbose("\t Event Forwarding Enable: %s\n",
                      this->event_config.event_fwd_enable ? "true" : "false");
    netos_log_verbose("\t Event Forwarding Server IP: %s\n",
                      this->event_config.event_fwd_ip.c_str());
    netos_log_verbose("\t Event Forwarding Server Port: %u\n",
                      this->event_config.event_fwd_port);
    netos_log_verbose("\t Event Forwarding Protocol: %s\n",
                      this->event_config.event_fwd_protocol_str().c_str());
    netos_log_verbose("\t Event Forwarding Timer Period (ms): %u\n",
                      this->event_config.timer_period_ms);
    netos_log_verbose("\t Event Storage Enable: %s\n",
                      this->event_config.event_storage_enable ? "true" : "false");
    netos_log_verbose("\t Event Storage Path: %s\n",
                      this->event_config.event_storage_path.c_str());
    netos_log_verbose("\t Event Storage File Prefix: %s\n",
                      this->event_config.event_storage_file_prefix.c_str());
}

netos_status network_filter_config::parse(Json::Value &root)
{
    this->drop_ipv4_fragments = root["drop_ipv4_fragments"].asBool();
    this->icmp_max_payload_len = root["icmp_max_payload_len"].asUInt();
    this->bypass_ipv4_checksum_verification =
              root["bypass_ipv4_checksum_verification"].asBool();

    return netos_status::NETOS_STATUS_SUCCESS;
}

void network_filter_config::print()
{
    netos_log_verbose("Filter Configuration:\n");
    netos_log_verbose("\t Drop IPv4 Fragments: %s\n",
                      this->drop_ipv4_fragments ? "true" : "false");
    netos_log_verbose("\t ICMP Max Payload Length: %u\n", this->icmp_max_payload_len);
    netos_log_verbose("\t Bypass IPv4 Checksum Verification: %s\n",
                      this->bypass_ipv4_checksum_verification ? "true" : "false");
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

void network_vlan_mapping::print()
{
    netos_log_verbose("\t Interface Name: %s\n", this->ifname.c_str());
    for (auto vlan_id_map : this->vlan_id_map) {
        netos_log_verbose("\t\t Ingress VLAN ID: %u, Egress VLAN ID: %u\n",
                          vlan_id_map.ingress_vlan_id,
                          vlan_id_map.egress_vlan_id);
    }
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

void network_vlan_config::print()
{
    netos_log_verbose("VLAN Mapping:\n");
    for (auto vlan_mapping : this->vlan_mapping) {
        vlan_mapping.print();
    }
    netos_log_verbose("\t Drop Double Tagged VLAN: %s\n",
                      this->drop_double_tagged_vlan ? "true" : "false");
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

void network_cloud_intf_config::print()
{
    netos_log_verbose("Cloud Interface Configuration:\n");
    netos_log_verbose("\t Cloud Interface Method: %s\n", this->method_str().c_str());
    netos_log_verbose("\t Cloud Interface Server IP: %s\n", this->server_ip.c_str());
    netos_log_verbose("\t Cloud Interface Server Port: %u\n", this->server_port);
    netos_log_verbose("\t Cloud Interface Stats Tx Interval (sec): %u\n",
                      this->stats_tx_interval_sec);
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
    ret = this->cloud_config_.parse(cloud_intf_config);
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    this->print();

    return netos_status::NETOS_STATUS_SUCCESS;
}

void network_config::print()
{
    netos_log_verbose("Network Configuration:\n");
    netos_log_verbose("------------------------------------------------\n");
    this->if_config_.print();
    this->vlan_config_.print();
    this->arp_config_.print();
    netos_log_verbose("\t Packet Buffer Pool Length: %u\n", this->packet_buf_pool_len);
    netos_log_verbose("\t Parsed Packet Buffer Pool Length: %u\n", this->parsed_pkt_buf_pool_len);
    this->log_config_.print();
    this->filter_config_.print();
    this->egress_config_.print();
    this->ids_config_.print();
    this->cloud_config_.print();
    netos_log_verbose("------------------------------------------------\n");
}

}

