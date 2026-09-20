#ifndef INTF_STATISTICS_H
#define INTF_STATISTICS_H

#include <stdint.h>

typedef struct {
    uint64_t n_tx;
    uint64_t n_sp_tx;
    uint64_t n_rr_tx;
    uint64_t n_pfifo_tx;
    uint64_t n_bfifo_tx;
} netos_egress_statistics_t;

#endif

