#ifndef NETOS_BUFFER_POOL_H
#define NETOS_BUFFER_POOL_H

#include <stdint.h>
#include <pthread.h>

#include "pkt_buffer.h"

/**
 * @brief - Defines buffer pool.
 */
typedef struct netos_buffer_pool {
    void            *mapped_mem;
    pkt_buffer_t    *free_buffers;
    uint32_t        size;
    pthread_mutex_t lock;
} netos_buffer_pool_t;

/**
 * @brief - Allocate the buffer pool.
 *
 * @param [in] n_pkt_buffers - number of packet buffers to allocate.
 *
 * @return Returns the buffer pool pointer.
 */
netos_buffer_pool_t *netos_buffer_pool_alloc(uint32_t n_pkt_buffers);

/**
 * @brief - Get a free buffer out of the buffer pool.
 *
 * @param [in] pool - allocated buffer pool.
 *
 * @return Returns the packet buffer.
 */
pkt_buffer_t *netos_buffer_pool_get_buffer(netos_buffer_pool_t *pool);

/**
 * @brief - Put back the buffer in the pol.
 *
 * @param [in] pool - allocated buffer pool.
 * @param [in] pkt_buf - packet buffer to return back.
 */
void netos_buffer_pool_put_buffer(netos_buffer_pool_t *pool, pkt_buffer_t *pkt_buf);

/**
 * @brief - Free the buffer pool.
 *
 * @param [in] pool - packet buffer pool.
 */
void netos_buffer_pool_free(netos_buffer_pool_t *pool);

#endif

