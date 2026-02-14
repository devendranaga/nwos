#include <iostream>
#include "statistics.h"
#include "logging.h"

namespace netos {

void statistics::initialize(const std::string &ifname)
{
    struct stats_intf *st;

    st = (struct stats_intf *)calloc(1, sizeof(struct stats_intf));
    if (!st) {
        return;
    }
    st->ifname = ifname;

    if (!this->stats_list_) {
        this->stats_list_ = st;
    } else {
        st->next = this->stats_list_;
        this->stats_list_ = st;
    }

    printf("initialize %s\n", ifname.c_str());
}

struct stats_intf *statistics::get_stats_intf(const std::string &ifname)
{
    struct stats_intf *st;

    for (st = this->stats_list_; st; st = st->next) {
        if (st->ifname == ifname) {
            return st;
        }
    }

    return NULL;
}

void statistics::inc_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.rx_count ++;
}

void statistics::inc_n_deny_rx(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_deny ++;
}

void statistics::inc_tx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->tx.tx_count ++;
}

void statistics::inc_eth_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_eth_rx ++;
}

void statistics::inc_vlan_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_vlan_rx ++;
}

void statistics::inc_ipv4_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_ipv4_rx ++;
}

void statistics::inc_ipv6_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_ipv6_rx ++;
}

void statistics::inc_arp_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_arp_rx ++;
}

void statistics::inc_tcp_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_tcp_rx ++;
}

void statistics::inc_udp_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_udp_rx ++;
}

void statistics::inc_icmp_rx_count(const std::string &ifname)
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    st = this->get_stats_intf(ifname);
    if (!st) {
        return;
    }

    st->rx.n_icmp_rx ++;
}

void statistics::print() {
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    for (st = this->stats_list_; st; st = st->next) {
        netos_log_info("interface <%s>\n", st->ifname.c_str());
        netos_log_info("rx_count: %lu\n", st->rx.rx_count);
        netos_log_info("n_deny_rx: %lu\n", st->rx.n_deny);
        netos_log_info("n_eth_rx: %lu\n", st->rx.n_eth_rx);
        netos_log_info("n_vlan_rx: %lu\n", st->rx.n_vlan_rx);
        netos_log_info("n_ipv4_rx: %lu\n", st->rx.n_ipv4_rx);
        netos_log_info("n_ipv6_rx: %lu\n", st->rx.n_ipv6_rx);
        netos_log_info("n_arp_rx: %lu\n", st->rx.n_arp_rx);
        netos_log_info("n_tcp_rx: %lu\n", st->rx.n_tcp_rx);
        netos_log_info("n_udp_rx: %lu\n", st->rx.n_udp_rx);
        netos_log_info("n_icmp_rx: %lu\n", st->rx.n_icmp_rx);
    }
}

}
