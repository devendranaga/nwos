#include "buffer_pool.h"
#include "statistics_ctx.h"
#include "egress_pfifo.h"

static void *netos_egress_pfifo_tx_queue_thread(void *ctx)
{
    netos_egress_pfifo_mgr_t *pfifo = ctx;
    uint32_t i;

    pthread_mutex_lock(&pfifo->pfifo_lock);
    pfifo->pkts_in_queue = false;
    pfifo->thread_started = true;
    pthread_cond_signal(&pfifo->pfifo_cond);
    pthread_mutex_unlock(&pfifo->pfifo_lock);

    while (1) {
        pthread_mutex_lock(&pfifo->pfifo_lock);
        while (!pfifo->pkts_in_queue && !pfifo->terminate_signal) {
            pthread_cond_wait(&pfifo->pfifo_cond, &pfifo->pfifo_lock);
        }

        if (pfifo->terminate_signal) {
            pthread_mutex_unlock(&pfifo->pfifo_lock);
            break;
        }

        pfifo->pkts_in_queue = false;

        pkt_buffer_t *pkt_buf = pfifo->queue.pkt_buf;

        for (i = 0; pkt_buf && (i < pfifo->in_pkts); i ++) {
            if (pkt_buf && pkt_buf->out_intf) {
                pkt_buffer_t *next = pkt_buf->next;

                if (pkt_buf->out_intf) {
                    netos_raw_socket_tx(pkt_buf->out_intf,
                                        pkt_buf->buffer,
                                        pkt_buf->tx_len);
                    netos_statistics_inc_pfifo_tx(pkt_buf->out_intf->stats_ctx);
                }

                netos_buffer_pool_put_buffer(pkt_buf->buffer_pool_ctx, pkt_buf);

                pkt_buf = next;
            }
        }

        pfifo->in_pkts = 0;

        pfifo->queue.pkt_buf = NULL;

        pthread_mutex_unlock(&pfifo->pfifo_lock);
    }

    return NULL;
}

netos_status_t
netos_egress_pfifo_init(netos_egress_pfifo_mgr_t *pfifo,
                        uint32_t n_pkts)
{
    netos_status_t ret;

    pfifo->n_pkts = n_pkts;
    pfifo->in_pkts = 0;
    pthread_mutex_init(&pfifo->pfifo_lock, NULL);
    pthread_cond_init(&pfifo->pfifo_cond, NULL);

    ret = netos_pthread_create_detached(&pfifo->pfifo_tid, 1, netos_egress_pfifo_tx_queue_thread, pfifo);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    pthread_mutex_lock(&pfifo->pfifo_lock);
    while (!pfifo->thread_started) {
        pthread_cond_wait(&pfifo->pfifo_cond, &pfifo->pfifo_lock);
    }
    pthread_mutex_unlock(&pfifo->pfifo_lock);

    return ret;
}

void netos_egress_pfifo_enque(void *ctx,
                              pkt_buffer_t *pkt_buf)
{
    netos_egress_pfifo_mgr_t *pfifo = ctx;

    if (pfifo->in_pkts > pfifo->n_pkts) {
        return;
    }

    pthread_mutex_lock(&pfifo->pfifo_lock);
    {
        if (!pfifo->queue.pkt_buf) {
            pfifo->queue.pkt_buf = pkt_buf;
            pfifo->queue.pkt_buf_last = pkt_buf;
        } else {
            pfifo->queue.pkt_buf_last->next = pkt_buf;
            pfifo->queue.pkt_buf_last = pkt_buf;
        }
        pfifo->pkts_in_queue = true;
        pfifo->in_pkts ++;
    }
    pthread_cond_signal(&pfifo->pfifo_cond);
    pthread_mutex_unlock(&pfifo->pfifo_lock);
}

void netos_egress_pfifo_deinit(netos_egress_pfifo_mgr_t *pfifo)
{
    if (!pfifo) {
        return;
    }

    pthread_mutex_lock(&pfifo->pfifo_lock);
    pfifo->terminate_signal = true;
    pthread_cond_signal(&pfifo->pfifo_cond);
    pthread_mutex_unlock(&pfifo->pfifo_lock);
}

