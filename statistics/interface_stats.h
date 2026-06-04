#ifndef NETOS_INTERFACE_STATS_H
#define NETOS_INTERFACE_STATS_H

#include <stdint.h>

typedef struct netos_interface_stats {
    uint64_t in_rx_invalid;
    uint64_t in_rx_valid;
    uint64_t in_rx_bytes;
} netos_interface_stats_t;

#endif

