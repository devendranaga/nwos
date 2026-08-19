#include "buffer_pool.h"
#include "statistics_ctx.h"
#include "egress_bfifo.h"

static void *netos_egress_bfifo_tx_queue_thread(void *ctx)
{
    netos_egress_bfifo_mgr_t *bfifo = ctx;
    uint32_t tx_bytes;

    pthread_mutex_lock(&bfifo->bfifo_lock);
    bfifo->pkts_in_queue = false;
    bfifo->thread_started = true;
    pthread_cond_signal(&bfifo->bfifo_cond);
    pthread_mutex_unlock(&bfifo->bfifo_lock);

    while (1) {
        pthread_mutex_lock(&bfifo->bfifo_lock);
        while (!bfifo->pkts_in_queue && !bfifo->terminate_signal) {
            pthread_cond_wait(&bfifo->bfifo_cond, &bfifo->bfifo_lock);
        }

        if (bfifo->terminate_signal) {
            pthread_mutex_unlock(&bfifo->bfifo_lock);
            break;
        }

        bfifo->pkts_in_queue = false;

        pkt_buffer_t *pkt_buf = bfifo->queue.pkt_buf;

        for (tx_bytes = 0; pkt_buf && (tx_bytes < bfifo->in_bytes);) {
            if (pkt_buf && pkt_buf->out_intf) {
                pkt_buffer_t *next = pkt_buf->next;

                if (pkt_buf->out_intf) {
                    netos_raw_socket_tx(pkt_buf->out_intf,
                                        pkt_buf->buffer,
                                        pkt_buf->tx_len);
                    netos_statistics_inc_bfifo_tx(pkt_buf->out_intf->stats_ctx);
                }

                netos_buffer_pool_put_buffer(pkt_buf->buffer_pool_ctx, pkt_buf);

                tx_bytes += pkt_buf->tx_len;
                pkt_buf = next;
            }
        }

        bfifo->in_bytes -= tx_bytes;
        bfifo->queue.pkt_buf = NULL;
        bfifo->queue.pkt_buf_last = NULL;

        pthread_mutex_unlock(&bfifo->bfifo_lock);
    }

    return NULL;
}

netos_status_t
netos_egress_bfifo_init(netos_egress_bfifo_mgr_t *bfifo,
                        uint32_t n_bytes)
{
    netos_status_t ret;

    bfifo->n_bytes = n_bytes;
    bfifo->in_bytes = 0;
    pthread_mutex_init(&bfifo->bfifo_lock, NULL);
    pthread_cond_init(&bfifo->bfifo_cond, NULL);

    ret = netos_pthread_create_detached(&bfifo->bfifo_tid,
                                        1,
                                        netos_egress_bfifo_tx_queue_thread,
                                        bfifo);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    pthread_mutex_lock(&bfifo->bfifo_lock);
    while (!bfifo->thread_started) {
        pthread_cond_wait(&bfifo->bfifo_cond, &bfifo->bfifo_lock);
    }
    pthread_mutex_unlock(&bfifo->bfifo_lock);

    return ret;
}

void netos_egress_bfifo_enque(void *ctx,
                              pkt_buffer_t *pkt_buf)
{
    netos_egress_bfifo_mgr_t *bfifo = ctx;

    pthread_mutex_lock(&bfifo->bfifo_lock);
    {
        if ((bfifo->in_bytes + pkt_buf->tx_len) > bfifo->n_bytes) {
            pthread_mutex_unlock(&bfifo->bfifo_lock);
            return;
        }

        if (!bfifo->queue.pkt_buf) {
            bfifo->queue.pkt_buf = pkt_buf;
            bfifo->queue.pkt_buf_last = pkt_buf;
        } else {
            bfifo->queue.pkt_buf_last->next = pkt_buf;
            bfifo->queue.pkt_buf_last = pkt_buf;
        }
        bfifo->pkts_in_queue = true;
        bfifo->in_bytes += pkt_buf->tx_len;
    }
    pthread_cond_signal(&bfifo->bfifo_cond);
    pthread_mutex_unlock(&bfifo->bfifo_lock);
}

void netos_egress_bfifo_deinit(netos_egress_bfifo_mgr_t *bfifo)
{
    if (!bfifo) {
        return;
    }

    pthread_mutex_lock(&bfifo->bfifo_lock);
    bfifo->terminate_signal = true;
    pthread_cond_signal(&bfifo->bfifo_cond);
    pthread_mutex_unlock(&bfifo->bfifo_lock);
}

