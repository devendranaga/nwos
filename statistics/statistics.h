#ifndef NETOS_STATISTICS_H
#define NETOS_STATISTICS_H

#include <stdatomic.h>
#include <stdint.h>

typedef struct netos_statistics_ingress {
    _Atomic uint64_t n_rx;
    _Atomic uint64_t n_parse_failed;
}netos_statistics_ingress_t;

typedef struct netos_statistics_egress {
    _Atomic uint64_t n_tx;
    _Atomic uint64_t n_sp_tx;
    _Atomic uint64_t n_rr_tx;
    _Atomic uint64_t n_pfifo_tx;
} netos_statistics_egress_t;

typedef struct netos_statistics {
    char                        *ifname;
    netos_statistics_ingress_t  ingress;
    netos_statistics_egress_t   egress;

    struct netos_statistics     *next;
} netos_statistics_t;

#endif

