#ifndef NETOS_EGRESS_SP_H
#define NETOS_EGRESS_SP_H

#include <stdint.h>
#include <pthread.h>
#include "raw_socket.h"
#include "pthread_intf.h"
#include "pkt_buffer.h"

// maps to the number of PCPs available in VLAN
#define NETOS_EGRESS_SP_MAX 8

typedef struct netos_egress_sp {
    pkt_buffer_t        *pkt_buf;
    pkt_buffer_t        *pkt_buf_last;
} netos_egress_sp_t;

typedef struct netos_egress_sp_mgr {
    netos_egress_sp_t   sp[NETOS_EGRESS_SP_MAX];
    bool                thread_started;
    bool                terminate_signal;
    bool                pkts_in_queue;
    pthread_t           sp_tid;
    pthread_mutex_t     sp_lock;
    pthread_cond_t      sp_cond;
} netos_egress_sp_mgr_t;

netos_status_t netos_egress_sp_init(netos_egress_sp_mgr_t *sp);

void netos_egress_sp_enque(netos_egress_sp_mgr_t *sp,
                           pkt_buffer_t *pkt_buf);
#endif
