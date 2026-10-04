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

void netos_statistics_inc_arp_ingress(void *stats_ptr);

void netos_statistics_inc_ipv4_ingress(void *stats_ptr);

void netos_statistics_inc_ipv6_ingress(void *stats_ptr);

void netos_statistics_inc_arp_rx();

void netos_statistics_inc_n_arp_fail();

uint32_t netos_statistics_get_ingress_stats(uint8_t *buf, uint32_t buf_len);

#endif

