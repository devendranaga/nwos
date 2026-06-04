#ifndef NETOS_PKT_BUFFER_H
#define NETOS_PKT_BUFFER_H

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include "raw_socket.h"

#define NETOS_PKT_BUFFER_LEN 4096u

typedef struct pkt_buffer {
    uint8_t             buffer[NETOS_PKT_BUFFER_LEN];
    uint32_t            offset;
    uint32_t            rx_len;
    uint32_t            tx_len;
    uint32_t            ref_count;
    pthread_mutex_t     lock;
    uint8_t             priority;
    struct timespec     rx_ts;

#define NETOS_PKT_BUFFER_SET_EVENT(__pkt_buf, __evt_type, __evt_desc) do {\
    (__pkt_buf)->event_type = __evt_type;\
    (__pkt_buf)->event_desc = __evt_desc; \
} while (0)

    uint32_t            event_type;
    uint32_t            event_desc;

#define NETOS_PKT_BUFFER_ADVANCE(__pkt_buf, __offset) do { \
    __pkt_buf->offset += __offset; \
} while (0)

    // from which interface this packet came from
    raw_socket_ctx_t    *in_intf;

    // on to which interface this packet will go
    raw_socket_ctx_t    *out_intf;

    // the allocator of this buffer .. back pointer to buffer pool
    void                *buffer_pool_ctx;

    // prev may be used in egress queueing but may not be used in all the cases
    struct pkt_buffer   *prev;
    struct pkt_buffer   *next;
} pkt_buffer_t;

void pkt_buffer_initialize(pkt_buffer_t *pkt_buf);

void pkt_buffer_ref_count_up(pkt_buffer_t *pkt_buf);

void pkt_buffer_ref_count_down(pkt_buffer_t *pkt_buf);

bool pkt_buffer_rx_frame_in_range(pkt_buffer_t *pkt_buf, uint32_t hdr_len);

void pkt_buffer_decode_byte(pkt_buffer_t *pkt_buf, uint8_t *u8);

void pkt_buffer_decode_2_bytes(pkt_buffer_t *pkt_buf, uint16_t *u16);

void pkt_buffer_decode_4_bytes(pkt_buffer_t *pkt_buf, uint32_t *u32);

void pkt_buffer_decode_bytes(pkt_buffer_t *pkt_buf, uint8_t *data, uint32_t data_len);

#endif

