#include <iostream>
#include <atomic>
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
    st->initialize(ifname);

    if (!this->stats_list_) {
        this->stats_list_ = st;
    } else {
        std::unique_lock<std::mutex> l(this->lock_);
        st->next = this->stats_list_;
        this->stats_list_ = st;
    }

    return st;
}

void stats_intf::inc_rx_count()
{
    this->rx.rx_count.fetch_add(1, std::memory_order_relaxed);
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
    this->rx.n_deny.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_tx_count()
{
    this->tx.tx_count.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_eth_rx_count()
{
    this->rx.n_eth_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_vlan_rx_count()
{
    this->rx.n_vlan_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_macsec_rx_count()
{
    this->rx.n_macsec_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_mka_rx_count()
{
    this->rx.n_mka_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_macsec_tx_count()
{
    this->tx.n_macsec_tx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_ipv4_rx_count()
{
    this->rx.n_ipv4_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_ipv6_rx_count()
{
    this->rx.n_ipv6_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_arp_rx_count()
{
    this->rx.n_arp_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_tcp_rx_count()
{
    this->rx.n_tcp_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_udp_rx_count()
{
    this->rx.n_udp_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_icmp_rx_count()
{
    this->rx.n_icmp_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::inc_icmpv6_rx_count()
{
    this->rx.n_icmpv6_rx.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::set_rx_queue_time_ns(uint64_t time_ns)
{
    this->perf.rx.rx_queue_time_ns.store(time_ns, std::memory_order_relaxed);
}

void stats_intf::set_parse_time_ns(uint64_t time_ns)
{
    this->perf.rx.parse_time_ns.store(time_ns, std::memory_order_relaxed);
}

void stats_intf::inc_egress_drop_buffer_full()
{
    this->egress.egress_drop_buffer_full.fetch_add(1, std::memory_order_relaxed);
}

void stats_intf::print()
{
    netos_log_info("interface <%s>\n", this->ifname.c_str());
    netos_log_info("rx_count: %lu\n", this->rx.rx_count.load(std::memory_order_relaxed));
    netos_log_info("n_deny_rx: %lu\n", this->rx.n_deny.load(std::memory_order_relaxed));
    netos_log_info("n_eth_rx: %lu\n", this->rx.n_eth_rx.load(std::memory_order_relaxed));
    netos_log_info("n_vlan_rx: %lu\n", this->rx.n_vlan_rx.load(std::memory_order_relaxed));
    netos_log_info("n_ipv4_rx: %lu\n", this->rx.n_ipv4_rx.load(std::memory_order_relaxed));
    netos_log_info("n_ipv6_rx: %lu\n", this->rx.n_ipv6_rx.load(std::memory_order_relaxed));
    netos_log_info("n_arp_rx: %lu\n", this->rx.n_arp_rx.load(std::memory_order_relaxed));
    netos_log_info("n_tcp_rx: %lu\n", this->rx.n_tcp_rx.load(std::memory_order_relaxed));
    netos_log_info("n_macsec_rx: %lu\n", this->rx.n_macsec_rx.load(std::memory_order_relaxed));
    netos_log_info("n_mka_rx: %lu\n", this->rx.n_mka_rx.load(std::memory_order_relaxed));
    netos_log_info("n_udp_rx: %lu\n", this->rx.n_udp_rx.load(std::memory_order_relaxed));
    netos_log_info("n_icmp_rx: %lu\n", this->rx.n_icmp_rx.load(std::memory_order_relaxed));
    netos_log_info("n_icmpv6_rx: %lu\n", this->rx.n_icmpv6_rx.load(std::memory_order_relaxed));
}

void statistics::print()
{
    struct stats_intf *st;

    std::unique_lock<std::mutex> l(this->lock_);

    for (st = this->stats_list_; st; st = st->next) {
        st->print();
    }
}

}
