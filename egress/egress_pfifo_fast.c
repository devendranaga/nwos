#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#include "netos_status.h"
#include "pthread_intf.h"
#include "raw_socket.h"
#include "statistics_ctx.h"
#include "egress_pfifo_fast.h"
#include "buffer_pool.h"
#include "netos_log.h"

void *netos_egress_pff_tx_queue_thread(void *ctx)
{
    netos_egress_pff_mgr_t *pff = ctx;

    pthread_mutex_lock(&pff->pff_lock);
    pff->pkts_in_queue = false;
    pff->thread_started = true;
    pthread_cond_signal(&pff->pff_cond);
    pthread_mutex_unlock(&pff->pff_lock);

    while (1) {
        pthread_mutex_lock(&pff->pff_lock);
        while (!pff->pkts_in_queue && !pff->terminate_signal) {
            pthread_cond_wait(&pff->pff_cond, &pff->pff_lock);
        }

        // manager thread signalled terminate, stop this thread
        if (pff->terminate_signal) {
            netos_log_info("pff thread signalled\n");
            pthread_mutex_unlock(&pff->pff_lock);
            break;
        }
        pff->pkts_in_queue = false;

        for (int i = 0; i < NETOS_EGRESS_PFIFO_FAST_BANDS_MAX; i ++) {
            netos_egress_band_t *pff_item = &pff->bands[i];

            while (pff_item->pkt_buf) {
                pkt_buffer_t *pkt_buf = pff_item->pkt_buf;

                // perform transmit of the packet
                pff_item->pkt_buf = pkt_buf->next;

                // egress the frame
                if (pkt_buf->out_intf) {
                    netos_raw_socket_tx(pkt_buf->out_intf,
                                        pkt_buf->buffer,
                                        pkt_buf->tx_len);
                    netos_statistics_inc_pfifo_fast_tx(pkt_buf->out_intf->stats_ctx);
                    netos_statistics_inc_tx(pkt_buf->out_intf->stats_ctx);
                }
                netos_buffer_pool_put_buffer(pkt_buf->buffer_pool_ctx, pkt_buf);
            }
        }

        pthread_mutex_unlock(&pff->pff_lock);
    }

    return NULL;
}

netos_status_t netos_egress_pff_init(netos_egress_pff_mgr_t *pff)
{
    uint32_t i;
    netos_status_t ret;

    for (i = 0; i < NETOS_EGRESS_PFIFO_FAST_BANDS_MAX; i ++) {
        pff->bands[i].pkt_buf       = NULL;
        pff->bands[i].pkt_buf_last  = NULL;
    }

    // initialize queue lock and the condition variable
    pthread_mutex_init(&pff->pff_lock, NULL);
    pthread_cond_init(&pff->pff_cond, NULL);

    // create pff tx thread for the 8 queues
    ret = netos_pthread_create(&pff->pff_tid, 1, netos_egress_pff_tx_queue_thread, pff);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    pthread_mutex_lock(&pff->pff_lock);
    while (!pff->thread_started) {
        pthread_cond_wait(&pff->pff_cond, &pff->pff_lock);
    }
    pthread_mutex_unlock(&pff->pff_lock);

    return ret;
}

void netos_egress_pff_deinit(netos_egress_pff_mgr_t *pff)
{
    if (!pff) {
        return;
    }

    pthread_mutex_lock(&pff->pff_lock);
    pff->terminate_signal = true;
    pthread_cond_signal(&pff->pff_cond);
    pthread_mutex_unlock(&pff->pff_lock);
    pthread_join(pff->pff_tid, NULL);
}

void netos_egress_pff_enque(void *ctx,
                           pkt_buffer_t *pkt_buf)
{
    netos_egress_pff_mgr_t *pff = ctx;
    uint32_t priority = pkt_buf->priority;

    /**
     * drop if the priority goes out of range.
     */
    if (priority >= NETOS_EGRESS_PFIFO_FAST_BANDS_MAX) {
        netos_buffer_pool_put_buffer(pkt_buf->buffer_pool_ctx, pkt_buf);
        return;
    }

    pthread_mutex_lock(&pff->pff_lock);
    {
        if (!pff->bands[priority].pkt_buf) {
            pff->bands[priority].pkt_buf = pkt_buf;
            pff->bands[priority].pkt_buf_last = pkt_buf;
        } else {
            pff->bands[priority].pkt_buf_last->next = pkt_buf;
            pff->bands[priority].pkt_buf_last = pkt_buf;
        }
        pff->pkts_in_queue = true;
    }
    pthread_cond_signal(&pff->pff_cond);
    pthread_mutex_unlock(&pff->pff_lock);
}

