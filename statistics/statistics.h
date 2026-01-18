#ifndef STATISTICS_STATISTICS_H
#define STATISTICS_STATISTICS_H

#include <unordered_map>
#include <string>
#include <mutex>

namespace netos {

struct stats_intf {
    uint64_t rx_count;

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
            this->stats_map_[ifname].rx_count++;
        }

        void print();

    private:
        std::unordered_map<std::string, stats_intf> stats_map_;
        std::mutex lock_;
        explicit statistics() { }
};

}

#endif
