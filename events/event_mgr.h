#ifndef NETOS_EVENT_MGR_H
#define NETOS_EVENT_MGR_H

#include <pthread.h>
#include "gcd.h"
#include "netos_config.h"
#include "event_buffer.h"
#include "mmap_intf.h"

/**
 * @brief - Defines an event manager.
 */
typedef struct netos_event_mgr {
    netos_event_buffer_t    *evt_buf;
    netos_event_info_t      *evt_list_head;
    netos_gcd_ctx_t         *gcd_ctx;
    netos_mmap_file_io_t    *evt_log_ptr;
    uint32_t                file_offset;
    pthread_t               tid;
    network_config_t        *config;
    pthread_mutex_t         evt_lock;
    pthread_cond_t          evt_cond;
} netos_event_mgr_t;

netos_status_t netos_event_mgr_init(netos_gcd_ctx_t *gcd_ctx,
                                    network_config_t *config);

void netos_event_mgr_add_event(netos_event_info_t *evt_info);

netos_event_info_t *netos_event_mgr_get_evt_buf();

#endif

