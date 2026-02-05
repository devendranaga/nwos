#ifndef NETOS_CLOUD_INTERFACE_STATS_INTERFACE_H
#define NETOS_CLOUD_INTERFACE_STATS_INTERFACE_H

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief - Interface receive statistics
 */
typedef struct __attribute__ ((__packed__)) {
    uint64_t rx_count;
    uint64_t n_eth_rx;
    uint64_t n_vlan_rx;
    uint64_t n_arp_rx;
    uint64_t n_ipv4_rx;
    uint64_t n_ipv6_rx;
    uint64_t n_tcp_rx;
    uint64_t n_udp_rx;
    uint64_t n_icmp_rx;
} stats_intf_rx_t;

/**
 * @brief - Interface transmit statistics
 */
typedef struct __attribute__ ((__packed__)) {
    uint64_t tx_count;
    uint64_t n_eth_tx;
    uint64_t n_vlan_tx;
    uint64_t n_arp_tx;
    uint64_t n_ipv4_tx;
    uint64_t n_ipv6_tx;
    uint64_t n_tcp_tx;
    uint64_t n_udp_tx;
    uint64_t n_icmp_tx;
} stats_intf_tx_t;

/**
 * @brief - Interface statistics
 */
typedef struct __attribute__ ((__packed__)) stats_interface {
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

#if defined(__cplusplus)
}
#endif

#endif
