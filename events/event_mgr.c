#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "netos_status.h"
#include "event_buffer.h"
#include "ethertypes.h"
#include "protocols.h"
#include "event_mgr.h"
#include "event_msg.h"
#include "common.h"
#include "gcd.h"
#include "netos_config.h"
#include "netos_log.h"

#define NETOS_EVENT_COUNT_MAX 100
#define NETOS_EVENT_BUFFERS_MAX 1024
#define NETOS_EVENT_FILE_SIZE_MAX 4 * 1024 * 1024
#define NETOS_EVENT_FILE_NAME_MAX 256

// find a way to make it within the global context instead of static global
static netos_event_mgr_t evt_mgr;

static netos_status_t netos_event_mgr_create_file(const char *filename)
{
    time_t now;
    struct tm *t;
    char filepath[NETOS_EVENT_FILE_NAME_MAX];

    now = time(0);
    t = gmtime(&now);

    snprintf(filepath, sizeof(filepath),
             "%s_%04d_%02d_%02d_%02d_%02d_%02d.bin",
             filename,
             t->tm_year + 1900,
             t->tm_mon + 1,
             t->tm_mday,
             t->tm_hour,
             t->tm_min,
             t->tm_sec);

    evt_mgr.evt_log_ptr = netos_mmap_open_file(filepath, NETOS_EVENT_FILE_SIZE_MAX);
    if (!evt_mgr.evt_log_ptr) {
        return NETOS_STATUS_FILE_OPEN_VIA_MMAP_FAILURE;
    }
    evt_mgr.file_offset = 0;

    netos_event_hdr_t *evt_hdr = evt_mgr.evt_log_ptr->memory;

    evt_hdr->magic = 0x4E574F53;
    evt_hdr->version = 1;

    evt_mgr.file_offset += sizeof(netos_event_hdr_t);

    return NETOS_STATUS_SUCCESS;
}

static void netos_event_mgr_write_event_log(netos_event_info_t *evt_info)
{
    netos_event_msg_t *evt_msg = (netos_event_msg_t *)(evt_mgr.evt_log_ptr->memory + evt_mgr.file_offset);
    uint32_t cur_offset = 0;
    const uint32_t default_max_size = sizeof(netos_event_msg_t) +\
                                      sizeof(netos_event_ipv6_data_t) +\
                                      sizeof(netos_event_l4_tcp_udp_t);
    netos_status_t ret;

    if ((evt_mgr.file_offset + default_max_size) >= NETOS_EVENT_FILE_SIZE_MAX) {
        netos_mmap_close_file(evt_mgr.evt_log_ptr, evt_mgr.file_offset);
        ret = netos_event_mgr_create_file(evt_mgr.config->event_config.storage_file);
        if (ret != NETOS_STATUS_SUCCESS) {
            return;
        }

        evt_msg = (netos_event_msg_t *)(evt_mgr.evt_log_ptr->memory + evt_mgr.file_offset);
    }

    evt_msg->type       = evt_info->s.type;
    evt_msg->desc       = evt_info->s.desc;
    strcpy(evt_msg->ifname, evt_info->s.ifname);
    evt_msg->sec        = evt_info->s.sec;
    evt_msg->nsec       = evt_info->s.nsec;
    evt_msg->frame_len  = evt_info->s.frame_len;
    evt_msg->ethertype  = evt_info->s.ethertype;

    cur_offset += sizeof(netos_event_msg_t);

    if (evt_info->s.ethertype == NETOS_ETHERTYPE_IPV4) {
        netos_event_ipv4_data_t *evt_ipv4 = (netos_event_ipv4_data_t *)(evt_msg->data);

        evt_ipv4->src_ipaddr    = evt_info->s.ip.v4.src_addr;
        evt_ipv4->dst_ipaddr    = evt_info->s.ip.v4.dst_addr;
        evt_ipv4->protocol      = evt_info->s.protocol;

        cur_offset += sizeof(netos_event_ipv4_data_t);

        if ((evt_info->s.protocol == NETOS_PROTOCOL_TCP) ||
            (evt_info->s.protocol == NETOS_PROTOCOL_UDP)) {
            netos_event_l4_tcp_udp_t *l4_proto = (netos_event_l4_tcp_udp_t *)(evt_ipv4->data);

            l4_proto->src_port = evt_info->s.l4.ports.src_port;
            l4_proto->dst_port = evt_info->s.l4.ports.dst_port;

            cur_offset += sizeof(netos_event_l4_tcp_udp_t);
        }
    }

    evt_mgr.file_offset += cur_offset;
}

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

        if (evt_mgr.evt_log_ptr) {
            netos_event_mgr_write_event_log(evt_data);
        }
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

    evt_mgr.config = config;

    if (config->event_config.store_events) {
        netos_event_mgr_create_file(config->event_config.storage_file);
    }

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

