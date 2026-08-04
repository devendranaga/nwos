#ifndef NETOS_PGEN_ARP_OPS_H
#define NETOS_PGEN_ARP_OPS_H

#include "raw_socket.h"

typedef struct {
    uint32_t    listen_time_sec; // how long to listen
    bool        dump_nw_data; // dump only
    bool        impersonate_device; // fake a device with below ids
    uint8_t     impersonate_addr[6];
    uint32_t    impersonate_ip;
} netos_pgen_arp_config_t;

void pgen_arp_listen(netos_raw_socket_ctx_t *raw, void *config);

#endif

