#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "netos_status.h"
#include "common.h"
#include "mmap_intf.h"
#include "rules_config.h"
#include "netos_log.h"

#define NETOS_RULE_TYPE_INDEX           0
#define NETOS_SRC_MAC_ADDR_INDEX        1
#define NETOS_SRC_IPADDR_INDEX          1
#define NETOS_SRC_IPADDR_INDEX_1        3
#define NETOS_DST_MAC_ADDR_INDEX        2
#define NETOS_DST_IPADDR_INDEX          2
#define NETOS_DST_IPADDR_INDEX_1        4
#define NETOS_ETHERTYPE_INDEX           3
#define NETOS_PROTOCOL_INDEX            3
#define NETOS_REWRITE_SRC_IP_INDEX      3
#define NETOS_REWRITE_DST_IP_INDEX      4

#define NETOS_SRC_MAC_ADDR_LEN_BYTES    7
#define NETOS_DST_MAC_ADDR_LEN_BYTES    7
#define NETOS_SRC_IPADDR_LEN_BYTES      6
#define NETOS_DST_IPADDR_LEN_BYTES      6
#define NETOS_ETHERTYPE_LEN_BYTES       9
#define NETOS_PROTOCOL_LEN_BYTES        8
#define NETOS_REWRITE_SRC_IPADDR_LEN_BYTES 14
#define NETOS_TO_DST_PORT_LEN_BYTES     11
#define NETOS_ICMP_TYPE_LEN_BYTES       9

struct netos_rule_token {
    char token[1024];
};

static struct netos_rule_token tokens[20];

static uint32_t netos_rule_tokenize(const char *buf)
{
    uint32_t count = 0;
    uint32_t j = 0;
    uint32_t i = 0;

    while (buf[i] != '\0') {
        if (buf[i] == ',') {
            tokens[count].token[j] = '\0';
            j = 0;
            count ++;
        } else {
            while ((j == 0) && (buf[i] == ' ')) {
                i ++;
            }
            tokens[count].token[j] = buf[i];
            j ++;
        }
        i ++;
    }

    tokens[count].token[j] = '\0';
    count ++;

    return count;
}

static netos_status_t netos_rule_set_rule_type(netos_rule_config_t *rule,
                                               uint32_t index)
{
    if (!strcmp(tokens[index].token, "allow")) {
        rule->rule_type = NETOS_RULE_TYPE_ALLOW;
    } else if (!strcmp(tokens[index].token, "alert")) {
        rule->rule_type = NETOS_RULE_TYPE_ALERT;
    } else if (!strcmp(tokens[index].token, "deny")) {
        rule->rule_type = NETOS_RULE_TYPE_DENY;
    } else if (!strcmp(tokens[index].token, "route")) {
        rule->rule_type = NETOS_RULE_TYPE_ROUTE;
    } else {
        return NETOS_STATUS_RULE_RULE_TYPE_INVALID;
    }

    return NETOS_STATUS_SUCCESS;
}

static uint32_t netos_rule_get_token_data(const char *token, uint32_t offset, char *data)
{
    uint32_t i = 0;

    while ((token[i + offset] != '>') && (token[i + offset] != '\0')) {
        data[i] = token[i + offset];
        i ++;
    }
    data[i] = '\0';

    return i;
}

static netos_status_t netos_rule_set_src_macaddr(netos_rule_config_t *rule,
                                                 uint32_t index)
{
    char mac_str[64] = {'\0'};
    const uint32_t len = NETOS_SRC_MAC_ADDR_LEN_BYTES + 2; // 1 for space + 1 for <
    uint32_t data_len = 0;
    netos_status_t ret;

    data_len = netos_rule_get_token_data(tokens[index].token, len, mac_str);
    if (data_len == 0) {
        return NETOS_STATUS_RULE_SRC_MAC_INVALID;
    }

    ret = netos_get_mac_addr_from_str(mac_str, rule->src_mac);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    rule->bits.src_mac = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_dst_macaddr(netos_rule_config_t *rule,
                                                 uint32_t index)
{
    char mac_str[64] = {'\0'};
    const uint32_t len = NETOS_DST_MAC_ADDR_LEN_BYTES + 2; // 1 for space + 1 for <
    uint32_t data_len = 0;
    netos_status_t ret;

    data_len = netos_rule_get_token_data(tokens[index].token, len, mac_str);
    if (data_len == 0) {
        return NETOS_STATUS_RULE_DST_MAC_INVALID;
    }

    ret = netos_get_mac_addr_from_str(mac_str, rule->dst_mac);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    rule->bits.dst_mac = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_ipaddr(uint32_t *ipaddr,
                                            uint32_t len_bytes,
                                            uint32_t index)
{
    char ipaddr_str[32] = {'\0'};
    const uint32_t len = len_bytes + 2; // 1 for space + 1 for <
    uint32_t data_len = 0;
    netos_status_t ret;

    data_len = netos_rule_get_token_data(tokens[index].token, len, ipaddr_str);
    if (data_len == 0) {
        return NETOS_STATUS_RULE_INVALID;
    }

    if (!strcmp(ipaddr_str, "any")) {
        *ipaddr = 0;
    } else {
        ret = netos_get_ipv4addr_from_str(ipaddr_str, ipaddr);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }
    }

    *ipaddr = htonl(*ipaddr);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_src_ipaddr(netos_rule_config_t *rule,
                                                uint32_t index)
{
    netos_status_t ret;

    ret = netos_rule_set_ipaddr(&rule->src.ipaddr, NETOS_SRC_IPADDR_LEN_BYTES, index);
    if (ret != NETOS_STATUS_SUCCESS) {
        return NETOS_STATUS_RULE_SRC_IPADDR_INVALID;
    }

    rule->bits.src_ip = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_dst_ipaddr(netos_rule_config_t *rule,
                                                uint32_t index)
{
    netos_status_t ret;

    ret = netos_rule_set_ipaddr(&rule->dst.ipaddr, NETOS_DST_IPADDR_LEN_BYTES, index);
    if (ret != NETOS_STATUS_SUCCESS) {
        return NETOS_STATUS_RULE_DST_IPADDR_INVALID;
    }

    rule->bits.dst_ip = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_rewrite_src_ipaddr(netos_rule_config_t *rule,
                                                        uint32_t index)
{
    netos_status_t ret;

    ret = netos_rule_set_ipaddr(&rule->dst.ipaddr, NETOS_REWRITE_SRC_IPADDR_LEN_BYTES, index);
    if (ret != NETOS_STATUS_SUCCESS) {
        return NETOS_STATUS_RULE_REWRITE_SRC_IP_INVALID;
    }

    rule->bits.rewrite_src_ip = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_ethertype(netos_rule_config_t *rule,
                                               uint32_t index)
{
    char ethertype_str[32] = {'\0'};
    const uint32_t len = NETOS_ETHERTYPE_LEN_BYTES + 2; // 1 for space + 1 for <
    uint32_t data_len = 0;
    netos_status_t ret;

    data_len = netos_rule_get_token_data(tokens[index].token, len, ethertype_str);
    if (data_len == 0) {
        return NETOS_STATUS_RULE_ETHERTYPE_INVALID;
    }

    if (!strcmp(ethertype_str, "any")) {
        rule->ethertype = 0; // match any ethertype
    } else {
        ret = netos_get_u16_hex_from_str(ethertype_str, &rule->ethertype);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }
    }

    rule->bits.ethertype = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_protocol(netos_rule_config_t *rule,
                                              uint32_t index)
{
    char protocol_str[32] = {'\0'};
    const uint32_t len = NETOS_PROTOCOL_LEN_BYTES + 2; // 1 for space + 1 for <
    uint32_t data_len = 0;
    netos_status_t ret;

    data_len = netos_rule_get_token_data(tokens[index].token, len, protocol_str);
    if (data_len == 0) {
        return NETOS_STATUS_RULE_PROTOCOL_INVALID;
    }

    if (!strcmp(protocol_str, "any")) {
        rule->protocol = 0; // match any protocol
    } else if (!strcmp(protocol_str, "tcp")) {
        rule->protocol = 6; // tcp
    } else if (!strcmp(protocol_str, "udp")) {
        rule->protocol = 17; // udp
    } else if (!strcmp(protocol_str, "icmp")) {
        rule->protocol = 1; // icmp
    } else {
        ret = netos_get_u32_from_str(protocol_str, &rule->protocol);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }
    }

    rule->bits.protocol = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_to_dst_port(netos_rule_config_t *rule,
                                                 uint32_t index)
{
    char dst_port_str[32] = {'\0'};
    const uint32_t len = NETOS_TO_DST_PORT_LEN_BYTES + 2; // 1 for space + 1 for <
    uint32_t data_len = 0;
    netos_status_t ret;

    data_len = netos_rule_get_token_data(tokens[index].token, len, dst_port_str);
    if (data_len == 0) {
        return NETOS_STATUS_RULE_TO_DST_PORT_INVALID;
    }

    ret = netos_get_u32_from_str(dst_port_str, &rule->l4.ports.dst_port);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    rule->bits.to_dst_port = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_icmp_type(netos_rule_config_t *rule,
                                               uint32_t index)
{
    char icmp_type_str[32] = {'\0'};
    const uint32_t len = NETOS_ICMP_TYPE_LEN_BYTES + 2; // 1 for space + 1 for <
    uint32_t data_len = 0;
    netos_status_t ret;

    data_len = netos_rule_get_token_data(tokens[index].token, len, icmp_type_str);
    if (data_len == 0) {
        return NETOS_STATUS_RULE_TO_DST_PORT_INVALID;
    }

    ret = netos_get_u32_from_str(icmp_type_str, &rule->l4.icmp.type);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    rule->bits.icmp_type = 1;

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_message(netos_rule_config_t *rule,
                                             uint32_t index)
{
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_rule_set_dst_ip(netos_rule_config_t *rule,
                                            uint32_t index)
{
    return NETOS_STATUS_SUCCESS;
}

typedef struct {
    char *name;
    netos_status_t (*callback)(netos_rule_config_t *rule, uint32_t index);
} netos_rule_index_config_t;

static const struct {
    uint32_t index;
    uint32_t n_callbacks;
    netos_rule_index_config_t config[10];
} netos_rule_metdata[] = {
    {
        NETOS_RULE_TYPE_INDEX,
        4,
        {
            {
                "allow",
                netos_rule_set_rule_type,
            },
            {
                "deny",
                netos_rule_set_rule_type,
            },
            {
                "alert",
                netos_rule_set_rule_type,
            },
            {
                "route",
                netos_rule_set_rule_type,
            }
        }
    },
    {
        NETOS_SRC_MAC_ADDR_INDEX,
        2,
        {
            {
                "src_mac",
                netos_rule_set_src_macaddr,
            },
            {
                "src_ip",
                netos_rule_set_src_ipaddr,
            }
        }
    },
    {
        NETOS_DST_MAC_ADDR_INDEX,
        2,
        {
            {
                "dst_mac",
                netos_rule_set_dst_macaddr,
            },
            {
                "dst_ip",
                netos_rule_set_dst_ipaddr,
            }
        }
    },
    {
        NETOS_ETHERTYPE_INDEX,
        3,
        {
            {
                "ethertype",
                netos_rule_set_ethertype,
            },
            {
                "protocol",
                netos_rule_set_protocol,
            },
            {
                "rewrite_src_ip",
                netos_rule_set_rewrite_src_ipaddr,
            }
        }
    },
    {
        NETOS_REWRITE_DST_IP_INDEX,
        5,
        {
            {
                "to_dst_port",
                netos_rule_set_to_dst_port,
            },
            {
                "icmp_type",
                netos_rule_set_icmp_type,
            },
            {
                "message",
                netos_rule_set_message,
            },
            {
                "rewrite_dst_ip",
                netos_rule_set_dst_ip,
            },
            {
                "src_ip",
                netos_rule_set_src_ipaddr
            }
        }
    }
};

static netos_rule_config_t *netos_rule_parse(const char *buf)
{
    netos_rule_config_t *rule;
    uint32_t n_tokens;
    uint32_t i;
    uint32_t j;

    n_tokens = netos_rule_tokenize(buf);
    if (n_tokens == 0) {
        return NULL;
    }

    rule = calloc(1, sizeof(netos_rule_config_t));
    if (!rule) {
        return NULL;
    }

    for (i = 0; (i < NETOS_SIZEOF_ARRAY(netos_rule_metdata)) && (i < n_tokens); i ++) {
        if (i == netos_rule_metdata[i].index) {
            bool found = false;

            for (j = 0; j < netos_rule_metdata[i].n_callbacks; j ++) {
                if (netos_rule_metdata[i].config[j].name &&
                    strstr(tokens[i].token,
                           netos_rule_metdata[i].config[j].name)) {
                    if (netos_rule_metdata[i].config[j].callback) {
                        netos_rule_metdata[i].config[j].callback(rule, i);
                        found = true;
                    }
                }
            }
            if (!found) {
                netos_log_error("failed to match any rule string with token [%s]\n",
                                tokens[i].token);
            }
        }
    }

    return rule;
}

netos_status_t netos_rule_config_parse(const char *file, netos_rules_t *rules)
{
    char buf[1024] = {0};
    FILE *fp;
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    fp = fopen(file, "r");
    if (!fp) {
        return NETOS_STATUS_RULE_FILE_OPEN_FAILURE;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        uint32_t len = strlen(buf) - 1;
        buf[len] = '\0';

        if ((buf[0] == '#') || (len <= 1)) {
            continue;
        }

        netos_rule_config_t *rule = netos_rule_parse(buf);
        if (!rule) {
            ret = NETOS_STATUS_RULE_INVALID;
            break;
        }

        rule->next = rules->rules;
        rules->rules = rule;
    }

    fclose(fp);

    netos_rule_config_print(rules);

    return ret;
}

void netos_rule_config_print(netos_rules_t *rules)
{
    netos_rule_config_t *rule;

    for (rule = rules->rules; rule; rule = rule->next) {
        netos_log_info("rule: {\n");
        netos_log_info("\t rule_type: %d\n", rule->rule_type);
        if (rule->bits.src_mac) {
            netos_log_info("\t src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            rule->src_mac[0], rule->src_mac[1],
                            rule->src_mac[2], rule->src_mac[3],
                            rule->src_mac[4], rule->src_mac[5]);
        }
        if (rule->bits.dst_mac) {
            netos_log_info("\t dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            rule->dst_mac[0], rule->dst_mac[1],
                            rule->dst_mac[2], rule->dst_mac[3],
                            rule->dst_mac[4], rule->dst_mac[5]);
        }
        if (rule->bits.ethertype) {
            netos_log_info("\t ethertype: 0x%04x\n", rule->ethertype);
        }
        if (rule->bits.src_ip) {
            netos_log_info("\t src_ip: 0x%x\n", rule->src.ipaddr);
        }
        if (rule->bits.dst_ip) {
            netos_log_info("\t dst_ip: 0x%x\n", rule->dst.ipaddr);
        }
        if (rule->bits.protocol) {
            netos_log_info("\t protocol: %d\n", rule->protocol);
        }
        if (rule->bits.to_dst_port) {
            netos_log_info("\t to_dst_port: %d\n", rule->l4.ports.dst_port);
        }
        if (rule->bits.icmp_type) {
            netos_log_info("\t icmp_type: %d\n", rule->l4.icmp.type);
        }
        netos_log_info("}\n");
    }
}

