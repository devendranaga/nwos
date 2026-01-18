#include "statistics.h"
#include "logging.h"

namespace netos {

void stats_intf::print(const std::string &ifname) {
    netos_log_info("Statistics on <%s>: {\n", ifname.c_str());
    netos_log_info("\t RX Count: %lu\n", this->rx_count);
    netos_log_info("}\n");
}

void statistics::print() {
    for (auto it : this->stats_map_) {
        it.second.print(it.first);
    }
}

}
