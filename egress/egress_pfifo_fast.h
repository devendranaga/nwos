#ifndef NETOS_EGRESS_PFIFO_FAST_H
#define NETOS_EGRESS_PFIFO_FAST_H

#include <stdint.h>
#include <pthread.h>
#include "raw_socket.h"
#include "pthread_intf.h"
#include "pkt_buffer.h"

// maps to the number of PCPs available in VLAN
#define NETOS_EGRESS_PFIFO_FAST_BANDS_MAX 3

typedef struct netos_egress_band {
    pkt_buffer_t        *pkt_buf;
    pkt_buffer_t        *pkt_buf_last;
} netos_egress_band_t;

typedef struct netos_egress_pff_mgr {
    netos_egress_band_t     bands[NETOS_EGRESS_PFIFO_FAST_BANDS_MAX];
    bool                    thread_started;
    bool                    terminate_signal;
    bool                    pkts_in_queue;
    pthread_t               pff_tid;
    pthread_mutex_t         pff_lock;
    pthread_cond_t          pff_cond;
} netos_egress_pff_mgr_t;

netos_status_t netos_egress_pff_init(netos_egress_pff_mgr_t *sp);

void netos_egress_pff_enque(void *ctx,
                            pkt_buffer_t *pkt_buf);

void netos_egress_pff_deinit(netos_egress_pff_mgr_t *sp);

#endif
