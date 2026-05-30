#include <stdio.h>
#include <string.h>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>

#include "netos_status.h"
#include "network_config.h"

static netos_status_t netos_config_parse_interface_config(network_config_t *config, xmlDocPtr doc, xmlNode *node)
{
    xmlNode *iter;
    uint32_t index = 0;

    for (iter = node->children; iter; iter = iter->next) {
        if ((iter->type == XML_ELEMENT_NODE) && (strcmp((char *)iter->name, "interface") == 0)) {
            xmlChar *val = xmlNodeListGetString(doc, iter->children, 1);
            if (!val) {
                return NETOS_STATUS_CONFIG_INVAL_XML;
            }

            config->if_config[index].ifname = strdup((char *)val);
            index ++;
        }
    }

    config->n_if_config = index;
    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_config_parse_interfaces(network_config_t *config, xmlDocPtr doc, xmlNode *root)
{
    xmlNode *node;
    netos_status_t ret;

    config->n_if_config = 0;

    for (node = root->children; node; node = node->next) {
        if ((node->type == XML_ELEMENT_NODE) && (strcmp((char *)node->name, "interface_list") == 0)) {
            ret = netos_config_parse_interface_config(config, doc, node);
            if (ret != NETOS_STATUS_SUCCESS) {
                return ret;
            }
        }
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_config_parse(network_config_t *config, const char *config_path)
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

    ret = netos_config_parse_interfaces(config, doc, root);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto end;
    }

    xmlFree(root);

    return ret;

end:
    if (root) {
        xmlFree(root);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    return NETOS_STATUS_CONFIG_INVAL_XML;
}

void netos_config_print(const network_config_t *config)
{
    uint32_t i;

    fprintf(stderr, "{\n");
    fprintf(stderr, "    ifconfig_list: {\n");
    for (i = 0; i < config->n_if_config; i ++) {
        fprintf(stderr, "        ifname: %s\n", config->if_config[i].ifname);
    }
    fprintf(stderr, "    }\n");
    fprintf(stderr, "}\n");
}

