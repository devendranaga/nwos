#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "mmap_intf.h"
#include "event_buffer.h"

netos_event_buffer_t *netos_event_buffer_init(uint32_t n_events)
{
    netos_event_buffer_t *pool;

    pool = calloc(1, sizeof(netos_event_buffer_t));
    if (!pool) {
        return NULL;
    }

    pthread_mutex_init(&pool->evt_lock, NULL);

    pool->size = (n_events + 1) * sizeof(netos_event_info_t);
    pool->mapped_mem = netos_mmap_alloc(pool->size);
    if (!pool->mapped_mem) {
        goto err;
    }

    pool->free_buffers = NULL;

    for (uint32_t i = 0; i < n_events; i ++) {
        netos_event_info_t *evt;

        evt = (pool->mapped_mem + (i * sizeof(netos_event_info_t)));

        evt->next = pool->free_buffers;
        pool->free_buffers = evt;
    }

    return pool;

err:
    if (pool) {
        free(pool);
    }

    return NULL;
}

netos_event_info_t *netos_event_buffer_get(netos_event_buffer_t *pool)
{
    netos_event_info_t *evt = NULL;

    pthread_mutex_lock(&pool->evt_lock);

    if (pool->free_buffers) {
        evt = pool->free_buffers;
        pool->free_buffers = pool->free_buffers->next;
    }

    pthread_mutex_unlock(&pool->evt_lock);

    return evt;
}

void netos_event_buffer_put(netos_event_buffer_t *pool, netos_event_info_t *evt)
{
    pthread_mutex_lock(&pool->evt_lock);

    if (!pool->free_buffers) {
        pool->free_buffers = evt;
        evt->next = NULL;
    } else {
        evt->next = pool->free_buffers;
        pool->free_buffers = evt;
    }

    pthread_mutex_unlock(&pool->evt_lock);
}

void netos_event_buffer_free(netos_event_buffer_t *pool)
{
    if (pool) {
        netos_mmap_free(pool->mapped_mem, pool->size);
        free(pool);
    }
}

