#include "egress_pfifo.h"

void *netos_egress_pfifo_tx_queue_thread(void *ctx)
{
    netos_egress_pfifo_mgr_t *pfifo = ctx;

    pthread_mutex_lock(&pfifo->pfifo_lock);
    pfifo->pkts_in_queue= false;
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
        while (pkt_buf) {
            pkt_buffer_t *pkt_buf = pfifo->queue.pkt_buf;

            if (pkt_buf->out_intf) {
                netos_raw_socket_tx(pkt_buf->out_intf,
                                    pkt_buf->buffer,
                                    pkt_buf->tx_len);
            }

            pkt_buf = pkt_buf->next;
        }
        pthread_mutex_unlock(&pfifo->pfifo_lock);
    }

    return NULL;
}

netos_status_t netos_egress_pfifo_init(netos_egress_pfifo_mgr_t *pfifo)
{
    netos_status_t ret;

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
    }
    pthread_cond_signal(&pfifo->pfifo_cond);
    pthread_mutex_unlock(&pfifo->pfifo_lock);
}

void netos_egress_pfifo_deinit(netos_egress_pfifo_mgr_t *pfifo)
{
    pthread_mutex_lock(&pfifo->pfifo_lock);
    pfifo->terminate_signal = true;
    pthread_cond_signal(&pfifo->pfifo_cond);
    pthread_mutex_unlock(&pfifo->pfifo_lock);
}

