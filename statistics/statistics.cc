#include <iostream>
#include "statistics.h"
#include "logging.h"

namespace netos {

stats_intf *statistics::initialize(const std::string &ifname)
{
    struct stats_intf *st;

    st = (struct stats_intf *)calloc(1, sizeof(struct stats_intf));
    if (!st) {
        return NULL;
    }
    st->ifname = ifname;

    if (!this->stats_list_) {
        this->stats_list_ = st;
    } else {
        std::unique_lock<std::mutex> l(this->lock_);
        st->next = this->stats_list_;
        this->stats_list_ = st;
    }

    printf("initialize %s\n", ifname.c_str());

    return st;
}

void stats_intf::inc_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);
    this->rx.rx_count ++;
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

void stats_intf::inc_n_deny_rx()
{
    std::unique_lock<std::mutex> l(this->lock);
    this->rx.n_deny ++;
}

void stats_intf::inc_tx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->tx.tx_count ++;
}

void stats_intf::inc_eth_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_eth_rx ++;
}

void stats_intf::inc_vlan_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_vlan_rx ++;
}

void stats_intf::inc_macsec_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_macsec_rx ++;
}

void stats_intf::inc_macsec_tx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->tx.n_macsec_tx ++;
}

void stats_intf::inc_ipv4_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_ipv4_rx ++;
}

void stats_intf::inc_ipv6_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_ipv6_rx ++;
}

void stats_intf::inc_arp_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_arp_rx ++;
}

void stats_intf::inc_tcp_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_tcp_rx ++;
}

void stats_intf::inc_udp_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_udp_rx ++;
}

void stats_intf::inc_icmp_rx_count()
{
    std::unique_lock<std::mutex> l(this->lock);

    this->rx.n_icmp_rx ++;
}

void stats_intf::print()
{
    std::unique_lock<std::mutex> l(this->lock);

    netos_log_info("interface <%s>\n", this->ifname.c_str());
    netos_log_info("rx_count: %lu\n", this->rx.rx_count);
    netos_log_info("n_deny_rx: %lu\n", this->rx.n_deny);
    netos_log_info("n_eth_rx: %lu\n", this->rx.n_eth_rx);
    netos_log_info("n_vlan_rx: %lu\n", this->rx.n_vlan_rx);
    netos_log_info("n_ipv4_rx: %lu\n", this->rx.n_ipv4_rx);
    netos_log_info("n_ipv6_rx: %lu\n", this->rx.n_ipv6_rx);
    netos_log_info("n_arp_rx: %lu\n", this->rx.n_arp_rx);
    netos_log_info("n_tcp_rx: %lu\n", this->rx.n_tcp_rx);
    netos_log_info("n_macsec_rx: %lu\n", this->rx.n_macsec_rx);
    netos_log_info("n_udp_rx: %lu\n", this->rx.n_udp_rx);
    netos_log_info("n_icmp_rx: %lu\n", this->rx.n_icmp_rx);
}

void statistics::print()
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    for (st = this->stats_list_; st; st = st->next) {
    }
}

}
