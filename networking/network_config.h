#ifndef NETOS_NETWORK_CONFIG_H
#define NETOS_NETWORK_CONFIG_H

#include <vector>
#include <jsoncpp/json/json.h>

#include "error_codes.h"

using namespace netos::lib;

namespace netos {

/**
 * @brief - Network ARP configuration
 */
struct network_arp_config {
    uint32_t arp_table_len;
    uint32_t arp_cache_mgmt_timer_intvl_sec;
    uint32_t arp_query_timer_intvl_sec;

    /**
     * @brief - Parse the ARP configuration
     *
     * @param root - JSON root root["arp_config"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
    void print();
};

/**
 * @brief - Network interface configuration
 */
struct network_if_config {
    std::vector<std::string> ifname;

    /**
     * @brief - Parse the interface configuration
     *
     * @param root - JSON root root["interface_list"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
    void print();
};

/**
 * @brief - Network Filter configuration
 */
struct network_filter_config {
    bool drop_ipv4_fragments;
    uint32_t icmp_max_payload_len;
    bool bypass_ipv4_checksum_verification;

    /**
     * @brief - Parse the Filter configuration
     *
     * @param root - Json root root["filter"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
    void print();
};

enum class egress_algorithm {
    ROUND_ROBIN
};

/**
 * @brief - Network egress configuration
 */
struct network_egress_config {
    uint32_t            number_of_queues;
    egress_algorithm    algorithm;

    std::string algorithm_str() const {
        switch (algorithm) {
            case egress_algorithm::ROUND_ROBIN:
                return "Round Robin";
            default:
                return "Unknown";
        }
    }

    /**
     * @brief - Parse the egress configuration
     *
     * @param root - JSON root root["egress"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
    void print();
};

enum class event_fwd_protocol {
    MQTT,
};

/**
 * @brief - Network event configuration
 */
struct network_event_config {
    bool                event_fwd_enable;
    std::string         event_fwd_ip;
    uint32_t            event_fwd_port;
    event_fwd_protocol  fwd_protocol;
    uint32_t            timer_period_ms;
    bool                event_storage_enable;
    std::string         event_storage_path;
    std::string         event_storage_file_prefix;

    std::string event_fwd_protocol_str() const {
        switch (fwd_protocol) {
            case event_fwd_protocol::MQTT:
                return "MQTT";
            default:
                return "Unknown";
        }
    }

    void print();
};

/**
 * @brief - Network IDS configuration
 */
struct network_ids_config {
    network_event_config event_config;

    /**
     * @brief - Parse the IDS configuration
     *
     * @param root - JSON root root["ids"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
    void print();
};

/**
 * @brief - Network logging configuration
 */
struct network_log_config {
    std::string debug_log_server_ip;
    uint32_t debug_log_server_port;
    bool log_pcap;
    std::string pcap_file_path;

    /**
     * @brief - Parse the logging configuration
     *
     * @param root - JSON root root["logging"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
    void print();
};

struct network_vlan_id_map {
    uint16_t ingress_vlan_id;
    uint16_t egress_vlan_id;

    void print();
};

struct network_vlan_mapping {
    std::string ifname;
    std::vector<network_vlan_id_map> vlan_id_map;

    netos_status parse(Json::Value &root);
    void print();
};

struct network_vlan_config {
    std::vector<network_vlan_mapping> vlan_mapping;
    bool drop_double_tagged_vlan;

    netos_status parse(Json::Value &root);
    void print();
};

enum class cloud_intf_method {
    UDP,
    MQTT,
    protobuf,
};

struct network_cloud_intf_config {
    cloud_intf_method   method;
    std::string         server_ip;
    uint32_t            server_port;
    uint32_t            stats_tx_interval_sec;

    std::string method_str() const {
        switch (method) {
            case cloud_intf_method::UDP:
                return "UDP";
            case cloud_intf_method::MQTT:
                return "MQTT";
            case cloud_intf_method::protobuf:
                return "Protobuf";
            default:
                return "Unknown";
        }
    }

    netos_status parse(Json::Value &root);
    void print();
};

/**
 * @brief - Network configuration
 */
struct network_config {
    public:
        network_if_config           if_config_;
        uint32_t                    packet_buf_pool_len;
        uint32_t                    parsed_pkt_buf_pool_len;
        network_vlan_config         vlan_config_;
        network_arp_config          arp_config_;
        network_log_config          log_config_;
        network_filter_config       filter_config_;
        network_egress_config       egress_config_;
        network_ids_config          ids_config_;
        network_cloud_intf_config   cloud_config_;

        ~network_config() { }

        /**
         * @brief - Get the singleton instance of the network configuration
         *
         * @return network_config*
         */
        static network_config *instance() {
            static network_config netw_config;
            return &netw_config;
        }

        /**
         * @brief - Parse the network configuration
         *
         * @param config - JSON configuration string
         * @return netos_status
         */
        netos_status parse(const std::string &config);
        void print();

    private:
        explicit network_config() { }
        network_config(const network_config &) = delete;
        network_config &operator=(const network_config &) = delete;
};

}

#endif

