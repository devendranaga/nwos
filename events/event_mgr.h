#ifndef NETOS_EVENT_MGR_H
#define NETOS_EVENT_MGR_H

#include <pthread.h>
#include "event_buffer.h"

typedef struct netos_event_mgr {
    netos_event_buffer_t    *evt_buf;
    netos_event_info_t      *evt_list_head;
    netos_event_info_t      *evt_list_tail;
    pthread_t               tid;
    pthread_mutex_t         evt_lock;
    pthread_cond_t          evt_cond;
} netos_event_mgr_t;

netos_status_t netos_event_mgr_init();

void netos_event_mgr_add_event(netos_event_info_t *evt_info);

netos_event_info_t *netos_event_mgr_get_evt_buf();

#endif

