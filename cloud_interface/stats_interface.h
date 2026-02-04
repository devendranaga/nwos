#ifndef NETOS_CLOUD_INTERFACE_STATS_INTERFACE_H
#define NETOS_CLOUD_INTERFACE_STATS_INTERFACE_H

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief - Interface receive statistics
 */
struct stats_intf_rx {
    uint64_t rx_count;
    uint64_t n_eth_rx;
    uint64_t n_vlan_rx;
    uint64_t n_arp_rx;
    uint64_t n_ipv4_rx;
    uint64_t n_ipv6_rx;
    uint64_t n_tcp_rx;
    uint64_t n_udp_rx;
    uint64_t n_icmp_rx;
};

/**
 * @brief - Interface transmit statistics
 */
struct stats_intf_tx {
    uint64_t tx_count;
    uint64_t n_eth_tx;
    uint64_t n_vlan_tx;
    uint64_t n_arp_tx;
    uint64_t n_ipv4_tx;
    uint64_t n_ipv6_tx;
    uint64_t n_tcp_tx;
    uint64_t n_udp_tx;
    uint64_t n_icmp_tx;
};

struct stats_interface {
    char            ifname[15];
    stats_intf_rx   rx;
    stats_intf_tx   tx;
} __attribute__ ((__packed__));

#if defined(__cplusplus)
}
#endif

#endif
