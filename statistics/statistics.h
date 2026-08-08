#ifndef NETOS_STATISTICS_H
#define NETOS_STATISTICS_H

#include <stdint.h>

typedef struct netos_statistics_ingress {
    uint64_t n_rx;
    uint64_t n_parse_failed;
}netos_statistics_ingress_t;

typedef struct netos_statistics_egress {
    uint64_t n_tx;
} netos_statistics_egress_t;

typedef struct netos_statistics {
    char                        *ifname;
    netos_statistics_ingress_t  ingress;
    netos_statistics_egress_t   egress;

    struct netos_statistics     *next;
} netos_statistics_t;

#endif

