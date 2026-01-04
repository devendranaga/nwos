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

struct pktgen_arp_config {
    bool            enable;
    uint8_t         eth_src_mac[NETOS_IDS_MACADDR_LEN];
    uint8_t         eth_dst_mac[NETOS_IDS_MACADDR_LEN];
    uint8_t         hw_type;
    uint32_t        protocol;
    uint8_t         ha_len;
    uint8_t         protocol_addr_len;
    uint8_t         arp_op;
    uint8_t         sender_hwaddr[NETOS_IDS_MACADDR_LEN];
    uint32_t        sender_protocol_addr;
    uint8_t         target_hwaddr[NETOS_IDS_MACADDR_LEN];
    uint32_t        target_protocol_addr;
    bool            randomize;
    bool            repeat;
    uint32_t        count;
    uint64_t        pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_vlan_config {
    bool                        enable;
    uint8_t                     eth_src_mac[NETOS_IDS_MACADDR_LEN];
    uint8_t                     eth_dst_mac[NETOS_IDS_MACADDR_LEN];
    uint16_t                    ethertype;
    bool                        randomize;
    std::vector<uint16_t>       vlan_ids;
    bool                        repeat;
    uint32_t                    count;
    uint64_t                    pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_ipv4_config {
    bool            enable;
    uint8_t         eth_src_mac[NETOS_IDS_MACADDR_LEN];
    uint8_t         eth_dst_mac[NETOS_IDS_MACADDR_LEN];
    bool            vlan_enable;
    std::vector<uint16_t>   vlan_ids;
    uint8_t         version;
    uint8_t         ihl;
    uint8_t         dscp;
    uint8_t         ecn;
    uint16_t        total_len;
    uint32_t        id;
    uint8_t         reserved;
    uint8_t         df;
    uint8_t         mf;
    uint16_t        frag_off;
    uint8_t         ttl;
    uint8_t         protocol;
    bool            hdr_checksum_autogen;
    uint32_t        hdr_checksum;
    uint32_t        src_addr;
    uint32_t        dst_addr;
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
    pktgen_arp_config arp_config;
    pktgen_vlan_config vlan_config;
    pktgen_ipv4_config ipv4_config;
    int parse(const std::string &filename);
    void print();

    private:
        explicit pktgen_config() = default;
};

}

}

#endif

