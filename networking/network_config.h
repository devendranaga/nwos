#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H

#include <stdint.h>
#include <net/if.h>

#include "netos_status.h"

#define NETOS_IFLIST_MAX 32

typedef struct network_if_config {
    char        *ifname;
    uint32_t    mtu;
} network_if_config_t;

typedef struct network_config {
    network_if_config_t if_config[NETOS_IFLIST_MAX];
    uint32_t            n_if_config;
    uint32_t            pkt_buffer_pool_len;
} network_config_t;

netos_status_t netos_config_parse(network_config_t *config, const char *config_path);

void netos_config_print(const network_config_t *config);

#endif
