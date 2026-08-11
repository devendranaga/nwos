#ifndef NETOS_STATISTICS_CTX_H
#define NETOS_STATISTICS_CTX_H

#include <pthread.h>
#include "netos_status.h"
#include "statistics.h"

/**
 * @brief - Defines statistics context.
 */
typedef struct {
    netos_statistics_t  *stat_head;
} netos_statistics_context_t;

netos_status_t netos_statistics_init();

void *netos_statistics_add(const char *ifname);

void netos_statistics_inc_rx(void *stat_ptr);

void netos_statistics_inc_tx(void *stat_ptr);

void netos_statistics_inc_sp_tx(void *stat_ptr);

void netos_statistics_inc_rr_tx(void *stat_ptr);

void netos_statistics_inc_pfifo_tx(void *stat_ptr);

void netos_statistics_inc_bfifo_tx(void *stat_ptr);

#endif

