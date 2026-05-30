#ifndef NETOS_BUFFER_POOL_H
#define NETOS_BUFFER_POOL_H

#include <stdint.h>
#include <pthread.h>

#include "pkt_buffer.h"

typedef struct netos_buffer_pool {
    void            *mapped_mem;
    pkt_buffer_t    *free_buffers;
    uint32_t        size;
    pthread_mutex_t lock;
} netos_buffer_pool_t;

netos_buffer_pool_t *netos_buffer_pool_alloc(uint32_t n_pkt_buffers);

pkt_buffer_t *netos_buffer_pool_get_buffer(netos_buffer_pool_t *pool);

void netos_buffer_pool_put_buffer(netos_buffer_pool_t *pool, pkt_buffer_t *pkt_buf);

void netos_buffer_pool_free(netos_buffer_pool_t *pool);

#endif

