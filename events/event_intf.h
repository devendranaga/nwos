#ifndef NETOS_EVENT_INTF_H
#define NETOS_EVENT_INTF_H

#include <stdint.h>

typedef struct netos_event_info {
    uint32_t event_type;
    uint32_t event_desc;
    uint32_t event_ts_sec;
    uint64_t event_ts_nsec;
    uint16_t rx_len;
} netos_event_info_t;

typedef struct netos_event_intf {
    void *(*init)();
    void (*add)(void *ctx, netos_event_info_t *evt_info);
    void (*deinit)(void *);
} netos_event_intf_t;

#endif

