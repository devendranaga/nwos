#include <stdint.h>
#include "netos_status.h"
#include "event_buffer.h"
#include "event_mgr.h"
#include "gcd.h"

#define NETOS_EVENT_BUFFERS_MAX 1024

// find a way to make it within the global context instead of static global
static netos_event_mgr_t evt_mgr;

netos_status_t netos_event_mgr_init(netos_gcd_ctx_t *gcd_ctx)
{
    evt_mgr.gcd_ctx = gcd_ctx;

    // allocate event buffers
    evt_mgr.evt_buf = netos_event_buffer_init(NETOS_EVENT_BUFFERS_MAX);
    if (!evt_mgr.evt_buf) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    evt_mgr.evt_list_head = NULL;
    pthread_mutex_init(&evt_mgr.evt_lock, NULL);
    pthread_cond_init(&evt_mgr.evt_cond, NULL);

    return NETOS_STATUS_SUCCESS;
}

void netos_event_mgr_add_event(netos_event_info_t *evt_info)
{
    pthread_mutex_lock(&evt_mgr.evt_lock);

    NETOS_EVENT_INFO_ADD_EVENT((evt_mgr.evt_list_head),
                               (evt_mgr.evt_list_tail),
                               evt_info);

    pthread_mutex_unlock(&evt_mgr.evt_lock);
}

netos_event_info_t *netos_event_mgr_get_evt_buf()
{
    return netos_event_buffer_get(evt_mgr.evt_buf);
}

