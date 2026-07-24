#include <stdint.h>
#include <pthread.h>

#include "netos_status.h"
#include "pthread_intf.h"
#include "raw_socket.h"
#include "egress_rr.h"
#include "buffer_pool.h"

void *netos_egress_rr_tx_queue_thread(void *ctx)
{
    netos_egress_rr_mgr_t *rr = ctx;

    pthread_mutex_lock(&rr->rr_lock);
    rr->pkts_in_queue = false;
    rr->thread_started = true;
    pthread_cond_signal(&rr->rr_cond);
    pthread_mutex_unlock(&rr->rr_lock);

    while (1) {
        pthread_mutex_lock(&rr->rr_lock);
        while (!rr->pkts_in_queue && !rr->terminate_signal) {
            pthread_cond_wait(&rr->rr_cond, &rr->rr_lock);
        }
        // manager thread signalled terminate, stop this thread
        if (rr->terminate_signal) {
            pthread_mutex_unlock(&rr->rr_lock);
            break;
        }
        rr->pkts_in_queue = false;

        /**
         * There can be cases where there are different items in the queue
         * with varying lengths. such as queue 1 can be 3 items and queue 2 can be 2.
         *
         * In this case, the count is used to count up or flag that there are still **some**
         * items in the queue and that the scheduler must repeat and look for the entry and
         * send out on the egress.
         */
        uint32_t count = 0;
        do {
            count = 0;
            for (int i = NETOS_EGRESS_RR_MAX - 1; i >= 0; i --) {
                netos_egress_rr_t *rr_item = &rr->rr[i];

                if (rr_item->pkt_buf) {
                    pkt_buffer_t *pkt_buf = rr_item->pkt_buf;

                    // perform transmit of the packet
                    rr_item->pkt_buf = pkt_buf->next;
                    if (pkt_buf->out_intf) {
                        netos_raw_socket_tx(pkt_buf->out_intf, pkt_buf->buffer, pkt_buf->tx_len);
                    }

                    netos_buffer_pool_put_buffer(pkt_buf->buffer_pool_ctx, pkt_buf);
                    if (rr_item->pkt_buf) {
                        count ++;
                    }
                }
            }
        } while (count > 0);

        pthread_mutex_unlock(&rr->rr_lock);
    }

    return NULL;
}

netos_status_t netos_egress_rr_init(netos_egress_rr_mgr_t *rr)
{
    uint32_t i;
    netos_status_t ret;

    for (i = 0; i < NETOS_EGRESS_RR_MAX; i ++) {
        rr->rr[i].pkt_buf       = NULL;
        rr->rr[i].pkt_buf_last  = NULL;
    }

    // initialize queue lock and the condition variable
    pthread_mutex_init(&rr->rr_lock, NULL);
    pthread_cond_init(&rr->rr_cond, NULL);

    // create rr tx thread for the 8 queues
    ret = netos_pthread_create_detached(&rr->rr_tid, 1, netos_egress_rr_tx_queue_thread, rr);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    pthread_mutex_lock(&rr->rr_lock);
    while (!rr->thread_started) {
        pthread_cond_wait(&rr->rr_cond, &rr->rr_lock);
    }
    pthread_mutex_unlock(&rr->rr_lock);

    return ret;
}

void netos_egress_rr_deinit(netos_egress_rr_mgr_t *rr)
{
    if (!rr) {
        return;
    }

    pthread_mutex_lock(&rr->rr_lock);
    rr->terminate_signal = true;
    pthread_cond_signal(&rr->rr_cond);
    pthread_mutex_unlock(&rr->rr_lock);
}

void netos_egress_rr_enque(void *ctx,
                           pkt_buffer_t *pkt_buf)
{
    netos_egress_rr_mgr_t *rr = ctx;
    uint32_t priority = pkt_buf->priority;

    pthread_mutex_lock(&rr->rr_lock);
    {
        if (!rr->rr[priority].pkt_buf) {
            rr->rr[priority].pkt_buf = pkt_buf;
            rr->rr[priority].pkt_buf_last = pkt_buf;
        } else {
            rr->rr[priority].pkt_buf_last->next = pkt_buf;
            rr->rr[priority].pkt_buf_last = pkt_buf;
        }
        rr->pkts_in_queue = true;
    }
    pthread_cond_signal(&rr->rr_cond);
    pthread_mutex_unlock(&rr->rr_lock);
}

