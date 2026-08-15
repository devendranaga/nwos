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

typedef struct netos_egress_bfifo {
    uint32_t max_bytes;
} netos_egress_bfifo_t;

typedef struct netos_egress_control {
    netos_egress_pfifo_t pfifo;
    netos_egress_bfifo_t bfifo;
} netos_egress_control_t;

typedef struct netos_vlan_entry {
    char        *ifname;
    uint16_t    ingress_vid;
    uint16_t    egress_vid;
    struct netos_vlan_entry *next;
} netos_vlan_entry_t;

typedef struct netos_vlan_table_config {
    netos_vlan_entry_t *entries;
} netos_vlan_table_config_t;

typedef struct netos_macsec_secy_entry_config {
    char        *ifname;
    uint32_t    cipher_suite;
    uint8_t     tx_sci[8];
    uint8_t     tx_an;
    uint8_t     rx_sci[8];
    uint8_t     rx_an;
    char        *macsec_key;

    struct netos_macsec_secy_entry_config *next;
} netos_macsec_secy_entry_config_t;

typedef struct netos_macsec_secy_config {
    uint8_t                             n_secy;
    netos_macsec_secy_entry_config_t    *secy_list;
} netos_macsec_secy_config_t;

typedef struct netos_event_config {
    uint32_t    tx_timer_intvl_sec;
    bool        store_events;
    char        *storage_file;
} netos_event_config_t;

/**
 * @brief - Defines network config.
 */
typedef struct network_config {
    network_if_config_t         if_config[NETOS_IFLIST_MAX];
    uint32_t                    n_if_config;
    uint32_t                    rx_pkt_buffer_pool_len;
    netos_protocol_config_t     protocol_config;
    netos_egress_control_t      egress_ctrl;
    netos_vlan_table_config_t   vlan_table_config;
    netos_macsec_secy_config_t  secy_config;
    netos_event_config_t        event_config;
    char                        *rule_file;
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

