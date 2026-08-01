#include <stdio.h>
#include <stdint.h>

#include "netos_status.h"
#include "buffer_pool.h"
#include "mmap_intf.h"

netos_buffer_pool_t *netos_buffer_pool_alloc(uint32_t n_pkt_buffers)
{
    netos_buffer_pool_t *pool;
    uint32_t i;

    pool = calloc(1, sizeof(netos_buffer_pool_t));
    if (!pool) {
        return NULL;
    }

    pthread_mutex_init(&pool->lock, NULL);

    // Allocate a memory mapped pool buffer
    pool->size = (n_pkt_buffers + 1) * sizeof(pkt_buffer_t);
    pool->mapped_mem = netos_mmap_alloc(pool->size);
    if (!pool->mapped_mem) {
        goto err;
    }

    for (i = 0; i < n_pkt_buffers; i ++) {
        pkt_buffer_t *ptr;

        ptr = (pool->mapped_mem + (i * sizeof(pkt_buffer_t)));
        pkt_buffer_initialize(ptr);

        /* double chaining not required so far when allocating free buffer pool. */
        ptr->prev = NULL;
        ptr->next = NULL;
        ptr->buffer_pool_ctx = pool;

        if (!pool->free_buffers) {
            pool->free_buffers = ptr;
        } else {
            ptr->next = pool->free_buffers;
            pool->free_buffers = ptr;
        }
    }

    return pool;

err:
    if (pool) {
        free(pool);
    }

    return NULL;
}

pkt_buffer_t *netos_buffer_pool_get_buffer(netos_buffer_pool_t *pool)
{
    pkt_buffer_t *ptr = NULL;

    pthread_mutex_lock(&pool->lock);

    if (pool->free_buffers) {
        ptr = pool->free_buffers;
        ptr->next = NULL;
        pkt_buffer_ref_count_up(ptr);
        pool->free_buffers = pool->free_buffers->next;
    }

    pthread_mutex_unlock(&pool->lock);

    return ptr;
}

void netos_buffer_pool_put_buffer(netos_buffer_pool_t *pool, pkt_buffer_t *pkt_buf)
{
    // give back the pkt_buf to the buffer pool.
    pkt_buffer_ref_count_down(pkt_buf);
    pkt_buffer_reset(pkt_buf);
    pkt_buf->next = NULL;

    pthread_mutex_lock(&pool->lock);

    if (!pool->free_buffers) {
        pool->free_buffers = pkt_buf;
    } else {
        pkt_buf->next = pool->free_buffers;
        pool->free_buffers = pkt_buf;
    }

    pthread_mutex_unlock(&pool->lock);
}

void netos_buffer_pool_free(netos_buffer_pool_t *pool)
{
    if (pool) {
        netos_mmap_free(pool->mapped_mem, pool->size);
        free(pool);
    }
}


