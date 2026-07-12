#ifndef NETOS_EGRESS_PFIFO_H
#define NETOS_EGRESS_PFIFO_H

#include <stdint.h>
#include <pthread.h>
#include "raw_socket.h"
#include "pthread_intf.h"
#include "pkt_buffer.h"

typedef struct netos_egress_pfifo_queue {
    pkt_buffer_t        *pkt_buf;
    pkt_buffer_t        *pkt_buf_last;
} netos_egress_pfifo_queue_t;

typedef struct netos_egress_pfifo_mgr {
    uint32_t                    n_pkts;
    uint32_t                    in_pkts;
    netos_egress_pfifo_queue_t  queue;
    bool                        thread_started;
    bool                        terminate_signal;
    bool                        pkts_in_queue;
    pthread_t                   pfifo_tid;
    pthread_mutex_t             pfifo_lock;
    pthread_cond_t              pfifo_cond;
} netos_egress_pfifo_mgr_t;

netos_status_t
netos_egress_pfifo_init(netos_egress_pfifo_mgr_t *sp,
                        uint32_t n_pkts);

void netos_egress_pfifo_enque(void *ctx,
                              pkt_buffer_t *pkt_buf);

void netos_egress_pfifo_deinit(netos_egress_pfifo_mgr_t *sp);

#endif
