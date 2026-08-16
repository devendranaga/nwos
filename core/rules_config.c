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
                                               uint32_t index,
                                               uint32_t n_tokens)
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
    if ((data_len == 0) || (data_len == 1)) {
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
    if ((data_len == 0) || (data_len == 1)) {
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
    if ((data_len == 0) || (data_len == 1)) {
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
    if ((data_len == 0) || (data_len == 1)) {
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
    if ((data_len == 0) || (data_len == 1)) {
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

static netos_rule_config_t *netos_rule_parse(const char *buf)
{
    netos_rule_config_t *rule;
    uint32_t n_tokens;
    bool invalid_token = true;
    netos_status_t ret;

    n_tokens = netos_rule_tokenize(buf);
    if (n_tokens == 0) {
        return NULL;
    }

    rule = calloc(1, sizeof(netos_rule_config_t));
    if (!rule) {
        return NULL;
    }

    // parse rule_type
    ret = netos_rule_set_rule_type(rule, NETOS_RULE_TYPE_INDEX, n_tokens);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    // parse src_mac / src_ip and so on
    if (strstr(tokens[NETOS_SRC_MAC_ADDR_INDEX].token, "src_mac")) {
        ret = netos_rule_set_src_macaddr(rule, NETOS_SRC_MAC_ADDR_INDEX);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto err;
        }

    } else if (strstr(tokens[NETOS_SRC_IPADDR_INDEX].token, "src_ip")) {
        ret = netos_rule_set_src_ipaddr(rule, NETOS_SRC_IPADDR_INDEX);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto err;
        }

    } else {
        netos_log_error("Invalid string <%s> expecting <src_mac/src_ip>\n",
                        tokens[NETOS_SRC_MAC_ADDR_INDEX].token);
        goto err;
    }

    // parse dst_mac / dst_ip and so on
    if (strstr(tokens[NETOS_DST_MAC_ADDR_INDEX].token, "dst_mac")) {
        ret = netos_rule_set_dst_macaddr(rule, NETOS_DST_MAC_ADDR_INDEX);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto err;
        }

    } else if (strstr(tokens[NETOS_DST_IPADDR_INDEX].token, "dst_ip")) {
        ret = netos_rule_set_dst_ipaddr(rule, NETOS_DST_IPADDR_INDEX);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto err;
        }

    } else {
        netos_log_error("Invalid string <%s> expecting <dst_mac/dst_ip>\n",
                        tokens[NETOS_DST_MAC_ADDR_INDEX].token);
        goto err;
    }

    if (strstr(tokens[NETOS_ETHERTYPE_INDEX].token, "ethertype")) {
        invalid_token = false;

        ret = netos_rule_set_ethertype(rule, NETOS_ETHERTYPE_INDEX);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto err;
        }

    } else if (strstr(tokens[NETOS_SRC_IPADDR_INDEX_1].token, "src_ip")) {
        invalid_token = false;

        if (strstr(tokens[NETOS_REWRITE_SRC_IP_INDEX].token, "rewrite_src_ip")) {
            ret = netos_rule_set_rewrite_src_ipaddr(rule, NETOS_REWRITE_SRC_IP_INDEX);
            if (ret != NETOS_STATUS_SUCCESS) {
                goto err;
            }

        } else {
            ret = netos_rule_set_src_ipaddr(rule, NETOS_SRC_IPADDR_INDEX_1);
            if (ret != NETOS_STATUS_SUCCESS) {
                goto err;
            }

        }
    } else if (strstr(tokens[NETOS_PROTOCOL_INDEX].token, "protocol")) {
        invalid_token = false;

        ret = netos_rule_set_protocol(rule, NETOS_PROTOCOL_INDEX);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto err;
        }

    }

    if (invalid_token) {
        netos_log_error("Invalid string <%s> expecting <ethertype/src_ip/protocol>\n",
                        tokens[NETOS_ETHERTYPE_INDEX].token);
        goto err;
    }

    return rule;

err:
    if (rule) {
        free(rule);
    }

    return NULL;
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
        netos_log_info("}\n");
    }
}

