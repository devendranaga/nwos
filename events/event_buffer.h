#ifndef NETOS_EVENT_BUFFER_H
#define NETOS_EVENT_BUFFER_H

#include <pthread.h>
#include "event_info.h"

typedef struct netos_event_buffer {
    void                *mapped_mem;
    netos_event_info_t  *free_buffers;
    uint32_t            size;
    uint32_t            n_buffers;
    pthread_mutex_t     evt_lock;
} netos_event_buffer_t;

netos_event_buffer_t *netos_event_buffer_init(uint32_t n_events);

netos_event_info_t *netos_event_buffer_get(netos_event_buffer_t *pool);

void netos_event_buffer_put(netos_event_buffer_t *pool, netos_event_info_t *evt);

void netos_event_buffer_free(netos_event_buffer_t *pool);

#endif

