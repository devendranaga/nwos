#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "netos_status.h"
#include "statistics.h"
#include "statistics_ctx.h"

static netos_statistics_context_t *stats_ctx;

netos_status_t netos_statistics_init()
{
    stats_ctx = calloc(1, sizeof(netos_statistics_context_t));
    if (!stats_ctx) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    return NETOS_STATUS_SUCCESS;
}

void *netos_statistics_add(const char *ifname)
{
    netos_statistics_t *stat;

    stat = calloc(1, sizeof(netos_statistics_t));
    if (!stat) {
        return NULL;
    }

    stat->ifname = strdup(ifname);

    stat->next = stats_ctx->stat_head;
    stats_ctx->stat_head = stat;

    return stat;
}

void netos_statistics_inc_rx(void *stat_ptr)
{
    netos_statistics_t *stat = stat_ptr;

    // incrementing via memory_order_relaxed manner does not create
    // problem when a cli is used to fetch these because the fetches
    // are atomic and the value does not have to be an instantaneous value.
    atomic_fetch_add_explicit(&stat->ingress.n_rx, 1, memory_order_relaxed);
}

void netos_statistics_inc_tx(void *stat_ptr)
{
    netos_statistics_t *stat = stat_ptr;

    atomic_fetch_add_explicit(&stat->egress.n_tx, 1, memory_order_relaxed);
}

void netos_statistics_inc_sp_tx(void *stat_ptr)
{
    netos_statistics_t *stat = stat_ptr;

    atomic_fetch_add_explicit(&stat->egress.n_sp_tx, 1, memory_order_relaxed);
}

void netos_statistics_inc_rr_tx(void *stat_ptr)
{
    netos_statistics_t *stat = stat_ptr;

    atomic_fetch_add_explicit(&stat->egress.n_rr_tx, 1, memory_order_relaxed);
}

void netos_statistics_inc_pfifo_tx(void *stat_ptr)
{
    netos_statistics_t *stat = stat_ptr;

    atomic_fetch_add_explicit(&stat->egress.n_pfifo_tx, 1, memory_order_relaxed);
}

