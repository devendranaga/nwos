#ifndef NETOS_RULES_CONFIG_H
#define NETOS_RULES_CONFIG_H

#include <stdint.h>
#include "protocol_const.h"

typedef struct __attribute__ ((__packed__)) {
    uint32_t src_mac        :1;
    uint32_t dst_mac        :1;
    uint32_t ethertype      :1;
    uint32_t src_ip         :1;
    uint32_t dst_ip         :1;
    uint32_t protocol       :1;
    uint32_t from_src_port  :1;
    uint32_t to_dst_port    :1;
    uint32_t icmp_type      :1;
    uint32_t icmp_code      :1;
    uint32_t message_str    :1;
} netos_rule_config_bits_t;

typedef enum {
    NETOS_RULE_TYPE_ALLOW = 1,
    NETOS_RULE_TYPE_ALERT,
    NETOS_RULE_TYPE_DENY,
    NETOS_RULE_TYPE_ROUTE,
} netos_rule_type_t;

typedef struct netos_rule_config {
    netos_rule_type_t           rule_type;
    uint8_t                     src_mac[NETOS_MACADDR_LEN];
    uint8_t                     dst_mac[NETOS_MACADDR_LEN];
    uint16_t                    ethertype;

    union {
        uint32_t                ipaddr;
        uint8_t                 ip6addr[NETOS_IPV6_ADDR_LEN];
    } src;

    union {
        uint32_t                ipaddr;
        uint8_t                 ip6addr[NETOS_IPV6_ADDR_LEN];
    } dst;

    union {
        uint32_t                ipaddr;
        uint8_t                 ip6addr[NETOS_IPV6_ADDR_LEN];
    } route_src;

    union {
        uint32_t                ipaddr;
        uint8_t                 ip6addr[NETOS_IPV6_ADDR_LEN];
    } route_dst;

    struct {
        union {
            uint16_t            src_port;
            uint16_t            dst_port;
        } ports;

        union {
            uint8_t             type;
            uint8_t             code;
        } icmp;
    } l4;

    char                        *message;
    netos_rule_config_bits_t    bits;
    struct netos_rule_config    *next;
} netos_rule_config_t;

typedef struct {
    netos_rule_config_t *rules;
} netos_rules_t;

netos_status_t netos_rule_config_parse(const char *file, netos_rules_t *rules);

#endif

