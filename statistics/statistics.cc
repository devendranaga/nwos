#include "statistics.h"
#include "logging.h"

namespace netos {

void statistics::print() {
    for (auto it : this->stats_map_) {
        netos_log_info("Statistics on <%s>: {\n", it.first.c_str());
        netos_log_info("\t Tx Count: %ju\n", it.second.tx.tx_count);
        netos_log_info("\t Tx Eth Count: %ju\n", it.second.tx.n_eth_tx);
        netos_log_info("\t Tx Arp Count: %ju\n", it.second.tx.n_arp_tx);
        netos_log_info("\t Tx IPv4 Count: %ju\n", it.second.tx.n_ipv4_tx);
        netos_log_info("\t Tx TCP Count: %ju\n", it.second.tx.n_tcp_tx);
        netos_log_info("\t Tx UDP Count: %ju\n", it.second.tx.n_udp_tx);
        netos_log_info("\t Tx ICMP Count: %ju\n", it.second.tx.n_icmp_tx);

        netos_log_info("\t Rx Count: %ju\n", it.second.rx.rx_count);
        netos_log_info("\t Rx Eth Count: %ju\n", it.second.rx.n_eth_rx);
        netos_log_info("\t Rx Arp Count: %ju\n", it.second.rx.n_arp_rx);
        netos_log_info("\t Rx IPv4 Count: %ju\n", it.second.rx.n_ipv4_rx);
        netos_log_info("\t Rx TCP Count: %ju\n", it.second.rx.n_tcp_rx);
        netos_log_info("\t Rx UDP Count: %ju\n", it.second.rx.n_udp_rx);
        netos_log_info("\t Rx ICMP Count: %ju\n", it.second.rx.n_icmp_rx);

        netos_log_info("}\n");
    }
}

}
