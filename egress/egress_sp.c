#include <stdint.h>
#include <pthread.h>

#include "netos_status.h"
#include "pthread_intf.h"
#include "raw_socket.h"
#include "egress_sp.h"
#include "buffer_pool.h"

void *netos_egress_sp_tx_queue_thread(void *ctx)
{
    netos_egress_sp_mgr_t *sp = ctx;

    pthread_mutex_lock(&sp->sp_lock);
    sp->pkts_in_queue = false;
    sp->thread_started = true;
    pthread_cond_signal(&sp->sp_cond);
    pthread_mutex_unlock(&sp->sp_lock);

    while (1) {
        pthread_mutex_lock(&sp->sp_lock);
        while (!sp->pkts_in_queue || !sp->terminate_signal) {
            pthread_cond_wait(&sp->sp_cond, &sp->sp_lock);
        }
        sp->pkts_in_queue = false;

        for (int i = NETOS_EGRESS_SP_MAX - 1; i >= 0; i --) {
            netos_egress_sp_t *sp_item = &sp->sp[i];

            while (sp_item->pkt_buf) {
                pkt_buffer_t *pkt_buf = sp_item->pkt_buf;

                // perform transmit of the packet
                sp_item->pkt_buf = pkt_buf->next;
                netos_buffer_pool_put_buffer(pkt_buf->buffer_pool_ctx, pkt_buf);
            }
        }

        pthread_mutex_unlock(&sp->sp_lock);
    }

    return NULL;
}

netos_status_t netos_egress_sp_init(netos_egress_sp_mgr_t *sp)
{
    uint32_t i;
    netos_status_t ret;

    for (i = 0; i < NETOS_EGRESS_SP_MAX; i ++) {
        sp->sp[i].pkt_buf       = NULL;
        sp->sp[i].pkt_buf_last  = NULL;
    }

    // initialize queue lock and the condition variable
    pthread_mutex_init(&sp->sp_lock, NULL);
    pthread_cond_init(&sp->sp_cond, NULL);

    // create sp tx thread for the 8 queues
    ret = netos_pthread_create_detached(&sp->sp_tid, netos_egress_sp_tx_queue_thread, sp);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    pthread_mutex_lock(&sp->sp_lock);
    while (!sp->thread_started) {
        pthread_cond_wait(&sp->sp_cond, &sp->sp_lock);
    }
    pthread_mutex_unlock(&sp->sp_lock);

    return ret;
}

void netos_egress_sp_enque(netos_egress_sp_mgr_t *sp,
                           pkt_buffer_t *pkt_buf)
{
    uint32_t priority = pkt_buf->priority;
    
    pthread_mutex_lock(&sp->sp_lock);
    {
        if (!sp->sp[priority].pkt_buf) {
            sp->sp[priority].pkt_buf = pkt_buf;
            sp->sp[priority].pkt_buf_last = pkt_buf;
        } else {
            sp->sp[priority].pkt_buf_last->next = pkt_buf;
            sp->sp[priority].pkt_buf_last = pkt_buf;
        }
        sp->pkts_in_queue = true;
    }
    pthread_cond_signal(&sp->sp_cond);
    pthread_mutex_unlock(&sp->sp_lock);
}
