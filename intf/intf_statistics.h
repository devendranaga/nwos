#ifndef NETOS_INTF_STATISTICS_H
#define NETOS_INTF_STATISTICS_H

#include <stdint.h>

typedef struct __attribute__ ((__packed__)) {
    uint64_t n_tx;
    uint64_t n_sp_tx;
    uint64_t n_rr_tx;
    uint64_t n_pfifo_tx;
    uint64_t n_bfifo_tx;
} netos_netctl_egress_statistics_t;

typedef struct __attribute__ ((__packed__)) {
    char     ifname[12];
    uint64_t n_rx;
    uint64_t n_arp_rx;
    uint64_t n_ipv4_rx;
    uint64_t n_ipv6_rx;
    uint64_t n_parse_failed;
} netos_netctl_ingress_statistics_t;

#endif

