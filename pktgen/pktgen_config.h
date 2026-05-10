#ifndef NETOS_IDS_PKTGEN_CONFIG_H
#define NETOS_IDS_PKTGEN_CONFIG_H

#include <stdint.h>
#include <string>

#include <jsoncpp/json/json.h>

#include "netos_macros.h"

namespace netos {

struct pktgen_eth_config {
    bool            enable;
    uint8_t         src_mac[NETOS_MACADDR_LEN];
    uint8_t         dst_mac[NETOS_MACADDR_LEN];
    uint16_t        ethertype;
    bool            randomize;
    bool            repeat;
    uint32_t        count;
    uint64_t        pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_arp_config {
    bool                        enable;
    uint8_t                     eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t                     eth_dst_mac[NETOS_MACADDR_LEN];
    std::vector<uint16_t>       vlan_ids;
    uint8_t                     hw_type;
    uint32_t                    protocol;
    uint8_t                     ha_len;
    uint8_t                     protocol_addr_len;
    uint8_t                     arp_op;
    uint8_t                     sender_hwaddr[NETOS_MACADDR_LEN];
    uint32_t                    sender_protocol_addr;
    uint8_t                     target_hwaddr[NETOS_MACADDR_LEN];
    uint32_t                    target_protocol_addr;
    bool                        randomize;
    bool                        repeat;
    uint32_t                    count;
    uint64_t                    pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_macsec_tci {
    uint32_t version:1;
    uint32_t es:1;
    uint32_t sc:1;
    uint32_t scb:1;
    uint32_t e:1;
    uint32_t c:1;
    uint32_t an:2;
} __attribute__ ((__packed__));

struct pktgen_macsec_config {
    bool                        enable;
    uint8_t                     eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t                     eth_dst_mac[NETOS_MACADDR_LEN];
    pktgen_macsec_tci           tci;
    uint8_t                     short_len;
    uint32_t                    pn;
    uint8_t                     sci_mac[NETOS_MACADDR_LEN];
    uint16_t                    sci_port_id;
    uint16_t                    macsec_ethertype;
    uint8_t                     icv[16];
    bool                        randomize;
    bool                        repeat;
    uint32_t                    count;
    uint64_t                    pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_vlan_config {
    bool                        enable;
    uint8_t                     eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t                     eth_dst_mac[NETOS_MACADDR_LEN];
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
    uint8_t         eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t         eth_dst_mac[NETOS_MACADDR_LEN];
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

struct pktgen_ipv6_config {
    bool            enable;
    uint8_t         eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t         eth_dst_mac[NETOS_MACADDR_LEN];
    bool            vlan_enable;
    std::vector<uint16_t>   vlan_ids;
    uint8_t         version;
    uint8_t         traffic_class;
    uint32_t        flow_label;
    uint16_t        payload_len;
    uint8_t         nh;
    uint8_t         hop_limit;
    uint8_t         src_addr[NETOS_IPV6_ADDR_LEN];
    uint8_t         dst_addr[NETOS_IPV6_ADDR_LEN];
    bool            randomize;
    bool            repeat;
    uint32_t        count;
    uint64_t        pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_icmp_config {
    bool            enable;
    uint8_t         eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t         eth_dst_mac[NETOS_MACADDR_LEN];
    uint32_t        src_addr;
    uint32_t        dst_addr;
    uint8_t         type;
    uint8_t         code;
    uint32_t        identifier;
    uint32_t        sequence_number;
    bool            randomize;
    bool            repeat;
    uint32_t        count;
    uint64_t        pkt_intvl_nsec;
    uint32_t        payload_len;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_tcp_config_flags {
    uint32_t         cwr    :1;
    uint32_t         ece    :1;
    uint32_t         urg    :1;
    uint32_t         ack    :1;
    uint32_t         psh    :1;
    uint32_t         rst    :1;
    uint32_t         syn    :1;
    uint32_t         fin    :1;
} __attribute__ ((__packed__));

struct pktgen_tcp_config {
    bool                    enable;
    uint8_t                 eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t                 eth_dst_mac[NETOS_MACADDR_LEN];
    uint32_t                ipv4_src_addr;
    uint32_t                ipv4_dst_addr;
    uint32_t                src_port;
    uint32_t                dst_port;
    uint32_t                seq_no;
    uint32_t                ack_no;
    pktgen_tcp_config_flags flags;
    uint32_t                window_size;
    uint32_t                urg_ptr;
    uint32_t                payload_len;
    bool                    randomize;
    bool                    repeat;
    uint32_t                count;
    uint64_t                pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_udp_config {
    bool                    enable;
    uint8_t                 eth_src_mac[NETOS_MACADDR_LEN];
    uint8_t                 eth_dst_mac[NETOS_MACADDR_LEN];
    uint32_t                src_addr;
    uint32_t                dst_addr;
    uint32_t                src_port;
    uint32_t                dst_port;
    uint32_t                payload_len;
    bool                    randomize;
    bool                    repeat;
    uint32_t                count;
    uint64_t                pkt_intvl_nsec;

    int parse(const Json::Value &r);
    void print();
};

struct pktgen_config {
    ~pktgen_config() = default;

    static pktgen_config *instance() {
        static pktgen_config config;
        return &config;
    }

    std::string             interface;
    pktgen_eth_config       eth_config;
    pktgen_arp_config       arp_config;
    pktgen_macsec_config    macsec_config;
    pktgen_vlan_config      vlan_config;
    pktgen_ipv4_config      ipv4_config;
    pktgen_ipv6_config      ipv6_config;
    pktgen_icmp_config      icmp_config;
    pktgen_tcp_config       tcp_config;
    pktgen_udp_config       udp_config;

    int parse(const std::string &filename);
    void print();

    private:
        explicit pktgen_config() = default;
};

}

#endif

