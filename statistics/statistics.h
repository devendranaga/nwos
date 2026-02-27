#ifndef STATISTICS_STATISTICS_H
#define STATISTICS_STATISTICS_H

#include <vector>
#include <string>
#include <mutex>

#include "stats_interface.h"
#include "performance_statistics.h"

namespace netos {

/**
 * @brief - Interface statistics
 */
struct stats_intf {
    std::string ifname;
    stats_intf_rx_t rx;
    stats_intf_tx_t tx;
    perf_statistics_t perf;
    struct stats_intf *next;
    std::mutex lock;

    stats_intf() {
        this->ifname = "";
        this->rx.rx_count = 0;
        this->rx.n_eth_rx = 0;
        this->rx.n_vlan_rx = 0;
        this->rx.n_arp_rx = 0;
        this->rx.n_macsec_rx = 0;
        this->rx.n_mka_rx = 0;
        this->rx.n_ipv4_rx = 0;
        this->rx.n_ipv6_rx = 0;
        this->rx.n_tcp_rx = 0;
        this->rx.n_udp_rx = 0;
        this->rx.n_icmp_rx = 0;
        this->rx.n_deny = 0;

        this->tx.tx_count = 0;
        this->tx.n_eth_tx = 0;
        this->tx.n_vlan_tx = 0;
        this->tx.n_arp_tx = 0;
        this->tx.n_macsec_tx = 0;
        this->tx.n_mka_tx = 0;
        this->tx.n_ipv4_tx = 0;
        this->tx.n_ipv6_tx = 0;
        this->tx.n_tcp_tx = 0;
        this->tx.n_udp_tx = 0;
        this->tx.n_icmp_tx = 0;
        this->perf.rx.parse_time_ns = 0;
    }
    ~stats_intf() { }

    void inc_rx_count();
    void inc_n_deny_rx();
    void inc_eth_rx_count();
    void inc_vlan_rx_count();
    void inc_arp_rx_count();
    void inc_macsec_rx_count();
    void inc_mka_rx_count();
    void inc_ipv4_rx_count();
    void inc_ipv6_rx_count();
    void inc_tcp_rx_count();
    void inc_udp_rx_count();
    void inc_icmp_rx_count();

    void inc_tx_count();
    void inc_eth_tx_count();
    void inc_vlan_tx_count();
    void inc_arp_tx_count();
    void inc_macsec_tx_count();
    void inc_mka_tx_count();
    void inc_ipv4_tx_count();
    void inc_ipv6_tx_count();
    void inc_tcp_tx_count();
    void inc_udp_tx_count();
    void inc_icmp_tx_count();
    void inc_n_deny_tx();

    void print();
};

class statistics {
    public:
        static statistics *instance() {
            static statistics instance;
            return &instance;
        }
        stats_intf *initialize(const std::string &ifname);
        struct stats_intf *get_stats_intf(const std::string &ifname);
        ~statistics() { }

        void print();

    private:
        stats_intf *stats_list_;
        std::mutex lock_;
        explicit statistics() { }
        explicit statistics(const statistics &) = delete;
        explicit statistics(statistics &&) = delete;
        statistics &operator=(const statistics &) = delete;
        statistics &operator=(statistics &&) = delete;
};

}

#endif

