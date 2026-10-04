#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "netos_status.h"
#include "statistics.h"
#include "statistics_ctx.h"
#include "intf_statistics.h"

static netos_statistics_context_t *stats_ctx;

static netos_global_statistics_t glob_stats;

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

    stat->ifname            = strdup(ifname);
    stat->next              = stats_ctx->stat_head;
    stats_ctx->stat_head    = stat;

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

void netos_statistics_inc_bfifo_tx(void *stat_ptr)
{
    netos_statistics_t *stat = stat_ptr;

    atomic_fetch_add_explicit(&stat->egress.n_bfifo_tx, 1, memory_order_relaxed);
}

void netos_statistics_inc_arp_ingress(void *stats_ptr)
{
    netos_statistics_t *stat = stats_ptr;

    atomic_fetch_add_explicit(&stat->ingress.n_arp_rx, 1, memory_order_relaxed);
}

void netos_statistics_inc_ipv4_ingress(void *stats_ptr)
{
    netos_statistics_t *stat = stats_ptr;

    atomic_fetch_add_explicit(&stat->ingress.n_ipv4_rx, 1, memory_order_relaxed);
}

void netos_statistics_inc_ipv6_ingress(void *stats_ptr)
{
    netos_statistics_t *stat = stats_ptr;

    atomic_fetch_add_explicit(&stat->ingress.n_ipv6_rx, 1, memory_order_relaxed);
}

void netos_statistics_inc_arp_rx()
{
    atomic_fetch_add_explicit(&glob_stats.arp.n_arp_rx, 1, memory_order_relaxed);
}

void netos_statistics_inc_n_arp_fail()
{
    atomic_fetch_add_explicit(&glob_stats.arp.n_arp_fail, 1, memory_order_relaxed);
}

uint32_t netos_statistics_get_ingress_stats(uint8_t *buf, uint32_t buf_len)
{
    netos_statistics_t *stat = stats_ctx->stat_head;
    uint32_t off = 0;
    uint32_t count = 0;

    while (stat && (off < buf_len)) {
        netos_netctl_ingress_statistics_t *ingress_stats;

        ingress_stats = (netos_netctl_ingress_statistics_t *)(buf + off);

        strncpy(ingress_stats->ifname, stat->ifname, sizeof(ingress_stats->ifname));

        ingress_stats->n_rx = atomic_load_explicit(&stat->ingress.n_rx, memory_order_relaxed);
        ingress_stats->n_arp_rx = atomic_load_explicit(&stat->ingress.n_arp_rx, memory_order_relaxed);
        ingress_stats->n_ipv4_rx = atomic_load_explicit(&stat->ingress.n_ipv4_rx, memory_order_relaxed);
        ingress_stats->n_ipv6_rx = atomic_load_explicit(&stat->ingress.n_ipv6_rx, memory_order_relaxed);
        ingress_stats->n_parse_failed = atomic_load_explicit(&stat->ingress.n_parse_failed, memory_order_relaxed);

        stat = stat->next;

        count ++;
    }

    return count;
}

