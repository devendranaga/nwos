#ifndef NETOS_IDS_PKTGEN_CONFIG_H
#define NETOS_IDS_PKTGEN_CONFIG_H

#include <stdint.h>
#include <string>

#include <jsoncpp/json/json.h>

#include "ids_macro_defs.h"

namespace netos {

namespace ids {

struct pktgen_eth_config {
    bool            enable;
    uint8_t         src_mac[NETOS_IDS_MACADDR_LEN];
    uint8_t         dst_mac[NETOS_IDS_MACADDR_LEN];
    uint16_t        ethertype;
    bool            randomize;
    bool            repeat;
    uint32_t        count;
    uint64_t        pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_config {
    ~pktgen_config() = default;

    static pktgen_config *instance() {
        static pktgen_config config;
        return &config;
    }

    std::string interface;
    pktgen_eth_config eth_config;
    int parse(const std::string &filename);
    void print();

    private:
        explicit pktgen_config() = default;
};

}

}

#endif

