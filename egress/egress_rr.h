#ifndef NETOS_EGRESS_RR_H
#define NETOS_EGRESS_RR_H

#include <stdint.h>
#include <pthread.h>
#include "raw_socket.h"
#include "pthread_intf.h"
#include "pkt_buffer.h"

// maps to the number of PCPs available in VLAN
#define NETOS_EGRESS_RR_MAX 8

typedef struct netos_egress_rr {
    pkt_buffer_t        *pkt_buf;
    pkt_buffer_t        *pkt_buf_last;
} netos_egress_rr_t;

typedef struct netos_egress_rr_mgr {
    netos_egress_rr_t   rr[NETOS_EGRESS_RR_MAX];
    bool                thread_started;
    bool                terminate_signal;
    bool                pkts_in_queue;
    pthread_t           rr_tid;
    pthread_mutex_t     rr_lock;
    pthread_cond_t      rr_cond;
} netos_egress_rr_mgr_t;

netos_status_t netos_egress_rr_init(netos_egress_rr_mgr_t *sp);

void netos_egress_rr_enque(void *ctx,
                           pkt_buffer_t *pkt_buf);

void netos_egress_rr_deinit(netos_egress_rr_mgr_t *sp);

#endif
