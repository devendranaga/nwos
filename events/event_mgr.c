#include <stdint.h>
#include "netos_status.h"
#include "event_buffer.h"
#include "event_mgr.h"
#include "common.h"
#include "gcd.h"
#include "netos_config.h"
#include "netos_log.h"

#define NETOS_EVENT_COUNT_MAX 100
#define NETOS_EVENT_BUFFERS_MAX 1024

// find a way to make it within the global context instead of static global
static netos_event_mgr_t evt_mgr;

static void netos_event_mgr_process_timer(void *ctx)
{
    netos_event_info_t *evt_data;
    netos_event_info_t *evt_data_next;
    uint32_t count = 0;

    pthread_mutex_lock(&evt_mgr.evt_lock);

    evt_data = evt_mgr.evt_list_head;
    // do not hog the event list, yield if there are over 100 events
    while (evt_data && (count < NETOS_EVENT_COUNT_MAX)) {
        evt_data_next = evt_data->next;

        netos_event_buffer_put(evt_mgr.evt_buf, evt_data);
        evt_data = evt_data_next;
        count ++;
    }

    pthread_mutex_unlock(&evt_mgr.evt_lock);
}

netos_status_t netos_event_mgr_init(netos_gcd_ctx_t *gcd_ctx,
                                    network_config_t *config)
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

    netos_gcd_timer_set_callback(gcd_ctx,
                                 config->event_config.tx_timer_intvl_sec,
                                 0,
                                 NULL,
                                 netos_event_mgr_process_timer);

    return NETOS_STATUS_SUCCESS;
}

void netos_event_mgr_add_event(netos_event_info_t *evt_info)
{
    pthread_mutex_lock(&evt_mgr.evt_lock);

    evt_info->next = evt_mgr.evt_list_head;
    evt_mgr.evt_list_head = evt_info;

    pthread_mutex_unlock(&evt_mgr.evt_lock);
}

netos_event_info_t *netos_event_mgr_get_evt_buf()
{
    return netos_event_buffer_get(evt_mgr.evt_buf);
}

