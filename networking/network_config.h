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

    /**
     * @brief - Parse the ARP configuration
     *
     * @param root - JSON root root["arp_config"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
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
};

/**
 * @brief - Network Filter configuration
 */
struct network_filter_config {
    bool drop_ipv4_fragments;

    /**
     * @brief - Parse the Filter configuration
     *
     * @param root - Json root root["filter"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
};

/**
 * @brief - Network logging configuration
 */
struct network_log_config {
    std::string debug_log_server_ip;
    uint16_t debug_log_server_port;
    bool log_pcap;
    std::string pcap_file_path;

    /**
     * @brief - Parse the logging configuration
     *
     * @param root - JSON root root["logging"]
     * @return netos_status
     */
    netos_status parse(Json::Value &root);
};

/**
 * @brief - Network configuration
 */
struct network_config {
    public:
        network_if_config if_config_;
        network_arp_config arp_config_;
        network_log_config log_config_;
        network_filter_config filter_config_;

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

    private:
        explicit network_config() { }
        network_config(const network_config &) = delete;
        network_config &operator=(const network_config &) = delete;
};

}

#endif

