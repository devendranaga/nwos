#ifndef NETOS_CLOUD_INTERFACE_STATS_INTERFACE_H
#define NETOS_CLOUD_INTERFACE_STATS_INTERFACE_H

#include <cstdint>

/**
 * @brief - Interface receive statistics
 */
typedef struct {
    std::atomic<std::uint64_t> rx_count;
    std::atomic<std::uint64_t> n_eth_rx;
    std::atomic<std::uint64_t> n_vlan_rx;
    std::atomic<std::uint64_t> n_arp_rx;
    std::atomic<std::uint64_t> n_macsec_rx;
    std::atomic<std::uint64_t> n_mka_rx;
    std::atomic<std::uint64_t> n_ipv4_rx;
    std::atomic<std::uint64_t> n_ipv6_rx;
    std::atomic<std::uint64_t> n_tcp_rx;
    std::atomic<std::uint64_t> n_udp_rx;
    std::atomic<std::uint64_t> n_icmp_rx;
    std::atomic<std::uint64_t> n_icmpv6_rx;
    std::atomic<std::uint64_t> n_deny;
} stats_intf_rx_t;

/**
 * @brief - Interface transmit statistics
 */
typedef struct {
    std::atomic<std::uint64_t> tx_count;
    std::atomic<std::uint64_t> n_eth_tx;
    std::atomic<std::uint64_t> n_vlan_tx;
    std::atomic<std::uint64_t> n_arp_tx;
    std::atomic<std::uint64_t> n_macsec_tx;
    std::atomic<std::uint64_t> n_mka_tx;
    std::atomic<std::uint64_t> n_ipv4_tx;
    std::atomic<std::uint64_t> n_ipv6_tx;
    std::atomic<std::uint64_t> n_tcp_tx;
    std::atomic<std::uint64_t> n_udp_tx;
    std::atomic<std::uint64_t> n_icmp_tx;
    std::atomic<std::uint64_t> n_icmpv6_tx;
} stats_intf_tx_t;

/**
 * @brief - Interface statistics
 */
typedef struct stats_interface {
    char            ifname[15];
    uint8_t         data[0];
} stats_interface_t;

#define STATS_INTERFACE_INIT(__buf, __intf_ptr, __ifname) {\
    __intf_ptr = (stats_interface_t *)__buf;\
    strcpy(__intf_ptr->ifname, __ifname);\
}

inline uint32_t stats_interface_get_tx_msg_len()
{
    return sizeof(stats_interface_t) + sizeof(stats_intf_tx_t);
}

#endif

