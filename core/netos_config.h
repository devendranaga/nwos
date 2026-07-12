#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>

#include "netos_status.h"

// Maximum number of interfaces
#define NETOS_IFLIST_MAX 32

/**
 * @brief - Defines interface config.
 */
typedef struct network_if_config {
    char        *ifname;
    uint32_t    mtu;
} network_if_config_t;

/**
 * @brief - Defines ARP configuration.
 */
typedef struct netos_arp_config {
    uint32_t arp_cache_size;
} netos_arp_config_t;

/**
 * @brief - Defines IPv4 configuration.
 */
typedef struct netos_ipv4_config {
    bool drop_fragments;
} netos_ipv4_config_t;

typedef struct netos_icmp_config {
    uint32_t echo_payload_len;
} netos_icmp_config_t;

/**
 * @brief - Defines protocol configuration.
 */
typedef struct netos_protocol_config {
    netos_arp_config_t  arp_config;
    netos_ipv4_config_t ipv4_config;
    netos_icmp_config_t icmp_config;
} netos_protocol_config_t;

typedef struct netos_egress_pfifo {
    uint32_t max_pkts;
} netos_egress_pfifo_t;

typedef struct netos_egress_control {
    netos_egress_pfifo_t pfifo;
} netos_egress_control_t;

/**
 * @brief - Defines network config.
 */
typedef struct network_config {
    network_if_config_t     if_config[NETOS_IFLIST_MAX];
    uint32_t                n_if_config;
    uint32_t                rx_pkt_buffer_pool_len;
    netos_protocol_config_t protocol_config;
    netos_egress_control_t  egress_ctrl;
} network_config_t;

/**
 * @brief - Parse configuration.
 *
 * @param [inout] config - configuration.
 * @param [in] config_path - configuration file.
 *
 * @return NETOS_STATUS_SUCESS on sucess and error code on failure.
 */
netos_status_t netos_config_parse(network_config_t *config, const char *config_path);

/**
 * @brief - Prints configuration.
 *
 * @return NETOS_STATUS_SUCESS on success and error code on failure.
 */
void netos_config_print(const network_config_t *config);

#endif

