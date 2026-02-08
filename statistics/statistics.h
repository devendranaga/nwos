#ifndef STATISTICS_STATISTICS_H
#define STATISTICS_STATISTICS_H

#include <unordered_map>
#include <string>
#include <mutex>

#include "stats_interface.h"

namespace netos {

/**
 * @brief - Interface statistics
 */
struct stats_intf {
    stats_intf_rx_t rx;
    stats_intf_tx_t tx;

    stats_intf() {
        this->rx.rx_count = 0;
        this->rx.n_eth_rx = 0;
        this->rx.n_vlan_rx = 0;
        this->rx.n_arp_rx = 0;
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
        this->tx.n_ipv4_tx = 0;
        this->tx.n_ipv6_tx = 0;
        this->tx.n_tcp_tx = 0;
        this->tx.n_udp_tx = 0;
        this->tx.n_icmp_tx = 0;
    }
    ~stats_intf() { }

    void print(const std::string &ifname);
};

class statistics {
    public:
        static statistics *instance() {
            static statistics instance;
            return &instance;
        }
        ~statistics() { }

        inline void inc_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.rx_count++;
        }

        inline void inc_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.tx_count++;
        }

        inline void inc_eth_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_eth_rx++;
        }

        inline void inc_vlan_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_vlan_rx++;
        }

        inline void inc_arp_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_arp_rx++;
        }

        inline void inc_ipv4_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_ipv4_rx++;
        }

        inline void inc_ipv6_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_ipv6_rx++;
        }

        inline void inc_tcp_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_tcp_rx++;
        }

        inline void inc_udp_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_udp_rx++;
        }

        inline void inc_icmp_rx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_icmp_rx++;
        }

        inline void inc_n_deny_rx(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].rx.n_deny ++;
        }

        inline void inc_eth_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_eth_tx++;
        }

        inline void inc_vlan_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_vlan_tx++;
        }

        inline void inc_arp_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_arp_tx++;
        }

        inline void inc_ipv4_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_ipv4_tx++;
        }

        inline void inc_ipv6_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_ipv6_tx++;
        }

        inline void inc_tcp_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_tcp_tx++;
        }

        inline void inc_udp_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_udp_tx++;
        }

        inline void inc_icmp_tx_count(const std::string &ifname) {
            std::unique_lock<std::mutex> l(this->lock_);
            this->stats_map_[ifname].tx.n_icmp_tx++;
        }

        void print();

    private:
        std::unordered_map<std::string, stats_intf> stats_map_;
        std::mutex lock_;
        explicit statistics() { }
        explicit statistics(const statistics &) = delete;
        explicit statistics(statistics &&) = delete;
        statistics &operator=(const statistics &) = delete;
        statistics &operator=(statistics &&) = delete;
};

}

#endif
