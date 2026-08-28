#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>

#include "netos_status.h"
#include "netos_config.h"
#include "common.h"

static netos_status_t netos_config_parse_interface_config(netos_config_t *config,
                                                          xmlDocPtr doc, xmlNode *node)
{
    xmlNode *iter;
    uint32_t index = 0;

    for (iter = node->children; iter; iter = iter->next) {
        if ((iter->type == XML_ELEMENT_NODE) &&
            (strcmp((char *)iter->name, "interface") == 0)) {
            xmlChar *val = xmlNodeListGetString(doc, iter->children, 1);
            if (!val) {
                return NETOS_STATUS_CONFIG_INVAL_XML;
            }

            config->if_config[index].ifname = strdup((char *)val);
            index ++;
            xmlFree(val);
        }
    }

    config->n_if_config = index;
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_config_get_string(char **str_ptr,
                                              xmlDocPtr doc, xmlNode *node)
{
    xmlChar *val = xmlNodeListGetString(doc, node->children, 1);

    if (!val) {
        return NETOS_STATUS_CONFIG_INVAL_XML;
    }

    *str_ptr = strdup((char *)val);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_config_get_u32(uint32_t *u32_ptr,
                                           xmlDocPtr doc, xmlNode *node)
{
    char *err_ptr = NULL;
    xmlChar *val = xmlNodeListGetString(doc, node->children, 1);

    if (!val) {
        return NETOS_STATUS_CONFIG_INVAL_XML;
    }

    *u32_ptr = strtoul((const char *)val, &err_ptr, 10);
    if (err_ptr && *err_ptr != '\0') {
        xmlFree(val);
        return NETOS_STATUS_CONFIG_INVAL_XML;
    }

    xmlFree(val);
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_config_get_bool(bool *bool_ptr,
                                            xmlDocPtr doc, xmlNode *node)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;
    xmlChar *val = xmlNodeListGetString(doc, node->children, 1);

    if (!val) {
        return NETOS_STATUS_CONFIG_INVAL_XML;
    }

    if (!strcasecmp((const char *)val, "true")) {
        *bool_ptr = true;
    } else if (!strcasecmp((const char *)val, "false")) {
        *bool_ptr = false;
    } else {
        ret = NETOS_STATUS_CONFIG_INVAL_XML;
    }

    xmlFree(val);
    return ret;
}

static netos_status_t netos_config_parse_rx_buffer_pool_size(netos_config_t *config,
                                                             xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_u32(&config->rx_pkt_buffer_pool_len,
                                doc, node);
}

static netos_status_t
netos_config_get_arp_cache_size(netos_config_t *config,
                                xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_u32(&config->protocol_config.arp_config.arp_cache_size,
                                doc, node);
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} arp_config_callbacks[] = {
    { "arp_cache_size", netos_config_get_arp_cache_size }
};

static netos_status_t
netos_config_parse_arp_config(netos_config_t *config,
                              xmlDocPtr doc, xmlNode *node)
{
    xmlNode *iter;
    netos_status_t ret = NETOS_STATUS_CONFIG_INVAL_XML;

    for (iter = node->children; iter; iter = iter->next) {
        if (iter->type == XML_ELEMENT_NODE) {
            for (uint32_t i = 0; i < sizeof(arp_config_callbacks) /
                                     sizeof(arp_config_callbacks[0]); i ++) {
                if (strcmp((const char *)iter->name, arp_config_callbacks[i].name) == 0) {
                    ret = arp_config_callbacks[i].callback_fn(config, doc, iter);
                    if (ret != NETOS_STATUS_SUCCESS) {
                        return ret;
                    }
                }
            }
        }
    }

    return ret;
}

static netos_status_t
netos_config_get_ipv4_drop_fragments(netos_config_t *config,
                                     xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_bool(&config->protocol_config.ipv4_config.drop_fragments,
                                 doc, node);
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} ipv4_config_callbacks[] = {
    { "drop_fragments", netos_config_get_ipv4_drop_fragments }
};

static netos_status_t
netos_config_parse_ipv4_config(netos_config_t *config,
                               xmlDocPtr doc, xmlNode *node)
{
    xmlNode *iter;
    netos_status_t ret = NETOS_STATUS_CONFIG_INVAL_XML;

    for (iter = node->children; iter; iter = iter->next) {
        if (iter->type == XML_ELEMENT_NODE) {
            for (uint32_t i = 0; i < sizeof(ipv4_config_callbacks) /
                                     sizeof(ipv4_config_callbacks[0]); i ++) {
                if (strcmp((const char *)iter->name, ipv4_config_callbacks[i].name) == 0) {
                    ret = ipv4_config_callbacks[i].callback_fn(config, doc, iter);
                    if (ret != NETOS_STATUS_SUCCESS) {
                        return ret;
                    }
                }
            }
        }
    }

    return ret;
}

static netos_status_t
netos_config_get_icmp_echo_payload_len(netos_config_t *config,
                                       xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_u32(&config->protocol_config.icmp_config.echo_payload_len,
                                doc, node);
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} icmp_config_callbacks[] = {
    { "min_echo_payload_len", netos_config_get_icmp_echo_payload_len }
};

static netos_status_t
netos_config_parse_icmp_config(netos_config_t *config,
                               xmlDocPtr doc, xmlNode *node)
{
    xmlNode *iter;
    netos_status_t ret = NETOS_STATUS_CONFIG_INVAL_XML;

    for (iter = node->children; iter; iter = iter->next) {
        if (iter->type == XML_ELEMENT_NODE) {
            for (uint32_t i = 0; i < sizeof(icmp_config_callbacks) /
                                     sizeof(icmp_config_callbacks[0]); i ++) {
                if (strcmp((const char *)iter->name,
                           icmp_config_callbacks[i].name) == 0) {
                    ret = icmp_config_callbacks[i].callback_fn(config, doc, iter);
                    if (ret != NETOS_STATUS_SUCCESS) {
                        return ret;
                    }
                }
            }
        }
    }

    return ret;
}

static netos_status_t
netos_config_parse_macsec_config(netos_config_t *config,
                                 xmlDocPtr doc, xmlNode *node)
{
    xmlNode *iter;
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    return ret;

    for (iter = node->children; iter; iter = iter->next) {
        if (iter->type == XML_ELEMENT_NODE) {
        }
    }

    return ret;
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} protocol_config_callbacks[] = {
    { "arp",    netos_config_parse_arp_config },
    { "ipv4",   netos_config_parse_ipv4_config },
    { "icmp",   netos_config_parse_icmp_config },
    { "macsec", netos_config_parse_macsec_config }
};

static netos_status_t
netos_config_parse_protocol_config(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node)
{
    xmlNode *node_ptr;
    netos_status_t ret;

    for (node_ptr = node->children; node_ptr; node_ptr = node_ptr->next) {
        for (uint32_t i = 0; i < sizeof(protocol_config_callbacks) /
                                 sizeof(protocol_config_callbacks[0]); i ++) {
            if ((node_ptr->type == XML_ELEMENT_NODE) &&
                (strcmp((const char *)node_ptr->name,
                        protocol_config_callbacks[i].name) == 0)) {
                ret = protocol_config_callbacks[i].callback_fn(config, doc, node_ptr);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return ret;
                }
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_config_get_pfifo_max_packets(netos_config_t *config,
                                     xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_u32(&config->egress_ctrl.pfifo.max_pkts,
                                doc, node);
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} pfifo_config_callbacks[] = {
    { "max_packets", netos_config_get_pfifo_max_packets }
};

static netos_status_t
netos_config_parse_pfifo_config(netos_config_t *config,
                                xmlDocPtr doc, xmlNode *node)
{
    xmlNode *node_ptr;
    netos_status_t ret;

    for (node_ptr = node->children; node_ptr; node_ptr = node_ptr->next) {
        for (uint32_t i = 0; i < sizeof(protocol_config_callbacks) /
                                 sizeof(protocol_config_callbacks[0]); i ++) {
            if ((node_ptr->type == XML_ELEMENT_NODE) &&
                (strcmp((const char *)node_ptr->name, pfifo_config_callbacks[i].name) == 0)) {
                ret = pfifo_config_callbacks[i].callback_fn(config, doc, node_ptr);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return ret;
                }
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} egress_config_callbacks[] = {
    { "pfifo",    netos_config_parse_pfifo_config },
};

static netos_status_t
netos_config_parse_egress_config(netos_config_t *config,
                                 xmlDocPtr doc, xmlNode *node)
{
    xmlNode *node_ptr;
    netos_status_t ret;

    for (node_ptr = node->children; node_ptr; node_ptr = node_ptr->next) {
        for (uint32_t i = 0;
             i < NETOS_SIZEOF_ARRAY(egress_config_callbacks);
             i ++) {
            if ((node_ptr->type == XML_ELEMENT_NODE) &&
                (strcmp((const char *)node_ptr->name,
                        egress_config_callbacks[i].name) == 0)) {
                ret = egress_config_callbacks[i].callback_fn(config, doc, node_ptr);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return ret;
                }
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_config_parse_event_tx_timer_val(netos_config_t *config,
                                                            xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_u32(&config->event_config.tx_timer_intvl_sec,
                                doc, node);
}

static netos_status_t netos_config_parse_store_events(netos_config_t *config,
                                                      xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_bool(&config->event_config.store_events,
                                 doc, node);
}

static netos_status_t netos_config_parse_event_storage_file(netos_config_t *config,
                                                            xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_string(&config->event_config.storage_file,
                                   doc, node);
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} event_config_callbacks[] = {
    { "event_transmit_timer_intvl_sec",     netos_config_parse_event_tx_timer_val },
    { "store_events",                       netos_config_parse_store_events },
    { "event_storage_file",                 netos_config_parse_event_storage_file },
};

static netos_status_t
netos_config_parse_event_config(netos_config_t *config,
                                xmlDocPtr doc, xmlNode *node)
{
    xmlNode *node_ptr;
    netos_status_t ret;

    for (node_ptr = node->children; node_ptr; node_ptr = node_ptr->next) {
        for (uint32_t i = 0; i < NETOS_SIZEOF_ARRAY(event_config_callbacks); i ++) {
            if ((node_ptr->type == XML_ELEMENT_NODE) &&
                (strcmp((const char *)node_ptr->name,
                        event_config_callbacks[i].name) == 0)) {
                ret = event_config_callbacks[i].callback_fn(config, doc, node_ptr);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return ret;
                }
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_config_parse_rule_file(netos_config_t *config,
                             xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_string(&config->rule_file, doc, node);
}

static netos_status_t
netos_config_parse_vlan_entry_interface(netos_vlan_entry_t *entry,
                                        xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_string(&entry->ifname, doc, node);
}

static netos_status_t
netos_config_parse_vlan_entry_in_vid(netos_vlan_entry_t *entry,
                                     xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_u32(&entry->ingress_vid, doc, node);
}

static netos_status_t
netos_config_parse_vlan_entry_out_vid(netos_vlan_entry_t *entry,
                                      xmlDocPtr doc, xmlNode *node)
{
    return netos_config_get_u32(&entry->egress_vid, doc, node);
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_vlan_entry_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} vlan_entry_callbacks[] = {
    { "interface",  netos_config_parse_vlan_entry_interface },
    { "in_vid",     netos_config_parse_vlan_entry_in_vid },
    { "out_vid",    netos_config_parse_vlan_entry_out_vid },
};

static netos_status_t
netos_config_parse_vlan_entry(netos_config_t *config,
                              xmlDocPtr doc, xmlNode *node)
{
    xmlNode *node_ptr;
    netos_vlan_entry_t entry = {
        .ifname         = NULL,
        .ingress_vid    = 0xffff,
        .egress_vid     = 0xffff,
        .next           = NULL
    };
    netos_status_t ret;

    for (node_ptr = node->children; node_ptr; node_ptr = node_ptr->next) {
        for (uint32_t i = 0; i < NETOS_SIZEOF_ARRAY(vlan_entry_callbacks); i ++) {
            if (node_ptr->type == XML_ELEMENT_NODE) {
                if (strcmp((const char *)node_ptr->name,
                           vlan_entry_callbacks[i].name) == 0) {
                    ret = vlan_entry_callbacks[i].callback_fn(&entry, doc, node_ptr);
                    if (ret != NETOS_STATUS_SUCCESS) {
                        return ret;
                    }
                }

                if ((entry.ifname != NULL) &&
                    (entry.ingress_vid != 0xffff) && (entry.egress_vid != 0xffff)) {
                    netos_vlan_entry_t *entry_ptr;

                    entry_ptr = calloc(1, sizeof(netos_vlan_entry_t));
                    if (!entry_ptr) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }
                    entry_ptr->ifname       = strdup(entry.ifname);
                    entry_ptr->ingress_vid  = entry.ingress_vid;
                    entry_ptr->egress_vid   = entry.egress_vid;

                    // add the entry
                    entry_ptr->next = config->vlan_table_config.entries;
                    config->vlan_table_config.entries = entry_ptr;

                    free(entry.ifname);

                    memset(&entry, 0, sizeof(netos_vlan_entry_t));
                    entry.ingress_vid   = 0xffff;
                    entry.egress_vid    = 0xffff;
                }
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_config_parse_vlan_table(netos_config_t *config,
                              xmlDocPtr doc, xmlNode *node)
{
    xmlNode *node_ptr;
    netos_status_t ret;

    for (node_ptr = node->children; node_ptr; node_ptr = node_ptr->next) {
        if ((node_ptr->type == XML_ELEMENT_NODE) &&
            (strcmp((const char *)node_ptr->name, "vlan_entry") == 0)) {
            ret = netos_config_parse_vlan_entry(config, doc, node_ptr);
            if (ret != NETOS_STATUS_SUCCESS) {
                return ret;
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

static const struct {
    const char      *name;
    netos_status_t  (*callback_fn)(netos_config_t *config,
                                   xmlDocPtr doc, xmlNode *node);
} config_callbacks[] = {
    { "interface_list",         netos_config_parse_interface_config },
    { "rx_buffer_pool_size",    netos_config_parse_rx_buffer_pool_size },
    { "protocols",              netos_config_parse_protocol_config },
    { "egress_control",         netos_config_parse_egress_config },
    { "events",                 netos_config_parse_event_config },
    { "rule_file",              netos_config_parse_rule_file },
    { "vlan_table",             netos_config_parse_vlan_table },
};

static netos_status_t
netos_config_parse_config_callbacks(netos_config_t *config,
                                    xmlDocPtr doc, xmlNode *node)
{
    xmlNode *node_ptr;
    netos_status_t ret;

    for (node_ptr = node->children; node_ptr; node_ptr = node_ptr->next) {
        for (uint32_t i = 0; i < sizeof(config_callbacks) /
                                 sizeof(config_callbacks[0]); i ++) {
            if ((node_ptr->type == XML_ELEMENT_NODE) &&
                (strcmp((const char *)node_ptr->name,
                        config_callbacks[i].name) == 0)) {
                ret = config_callbacks[i].callback_fn(config, doc, node_ptr);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return ret;
                }
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

#define NETOS_CONFIG_CLEAR(__config) do {\
    __config->rule_file = NULL;\
    __config->vlan_table_config.entries = NULL;\
} while (0)

netos_status_t netos_config_parse(netos_config_t *config, const char *config_path)
{
    netos_status_t ret;
    xmlDocPtr doc = xmlReadFile(config_path, NULL, 0);

    if (!doc) {
        return NETOS_STATUS_CONFIG_INVAL_XML;
    }

    xmlNode *root = xmlDocGetRootElement(doc);
    if (!root) {
        goto end;
    }

    if (strcmp((char *)root->name, "configuration") != 0) {
        goto end;
    }

    NETOS_CONFIG_CLEAR(config);

    ret = netos_config_parse_config_callbacks(config, doc, root);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto end;
    }

    xmlFree(root);

    netos_config_print(config);

    return ret;

end:
    if (root) {
        xmlFree(root);
    }

    return NETOS_STATUS_CONFIG_INVAL_XML;
}

void netos_config_print(const netos_config_t *config)
{
    uint32_t i;

    fprintf(stderr, "{\n");
    fprintf(stderr, "    ifconfig_list: {\n");
    for (i = 0; i < config->n_if_config; i ++) {
        fprintf(stderr, "        ifname: %s\n", config->if_config[i].ifname);
    }
    fprintf(stderr, "    }\n");
    fprintf(stderr, "    rx_buffer_pool_size: %d\n", config->rx_pkt_buffer_pool_len);
    fprintf(stderr, "    events: {\n");
    fprintf(stderr, "        event_transmit_timer_intvl_sec: %d\n", config->event_config.tx_timer_intvl_sec);
    fprintf(stderr, "        store_events: %d\n", config->event_config.store_events);
    fprintf(stderr, "        storage_file: %s\n", config->event_config.storage_file);
    fprintf(stderr, "    }\n");
    fprintf(stderr, "    protocols: {\n");
    fprintf(stderr, "        arp: {\n");
    fprintf(stderr, "            arp_cache_size: %d\n",
                    config->protocol_config.arp_config.arp_cache_size);
    fprintf(stderr, "        }\n");
    fprintf(stderr, "        ipv4: {\n");
    fprintf(stderr, "            drop_fragments: %s\n",
                    config->protocol_config.ipv4_config.drop_fragments ? "True": "False");
    fprintf(stderr, "        }\n");
    fprintf(stderr, "        icmp: {\n");
    fprintf(stderr, "            min_echo_payload_len: %d\n",
                    config->protocol_config.icmp_config.echo_payload_len);
    fprintf(stderr, "        }\n");
    fprintf(stderr, "    }\n");
    fprintf(stderr, "    vlan_table: {\n");
    for (netos_vlan_entry_t *entry = config->vlan_table_config.entries;
         entry;
         entry = entry->next) {
        fprintf(stderr, "        vlan_entry: {\n");
        fprintf(stderr, "            ifname: %s\n", entry->ifname);
        fprintf(stderr, "            ingress_vid: %d\n", entry->ingress_vid);
        fprintf(stderr, "            egress_vid: %d\n", entry->egress_vid);
        fprintf(stderr, "        }\n");
    }
    fprintf(stderr, "    }\n");
    fprintf(stderr, "    egress_control: {\n");
    fprintf(stderr, "        pfifo:{\n");
    fprintf(stderr, "            max_packets: %d\n",
                    config->egress_ctrl.pfifo.max_pkts);
    fprintf(stderr, "        }\n");
    fprintf(stderr, "    }\n");
    if (config->rule_file) {
        fprintf(stderr, "    rule_file: %s\n", config->rule_file);
    }
    fprintf(stderr, "}\n");
}

