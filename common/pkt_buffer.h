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
#include "perf_intf.h"

#define NETOS_PKT_BUFFER_LEN 4096u

typedef struct pkt_buffer {
    // buffer for transmit and receive
    uint8_t             buffer[NETOS_PKT_BUFFER_LEN];

    // pointer in the buffer
    uint32_t            offset;

    // receive length
    uint32_t            rx_len;

    // transmit length
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

    // ip header offset
    uint32_t            ipv4_offset;

    // perf event related to this frame
    netos_perf_event_t  perf_evt;

    // prev may be used in egress queueing but may not be used in all the cases
    struct pkt_buffer   *prev;
    struct pkt_buffer   *next;
} pkt_buffer_t;

static inline void pkt_buffer_reset(pkt_buffer_t *pkt_buf)
{
    pkt_buf->offset     = 0;
    pkt_buf->rx_len     = 0;
    pkt_buf->tx_len     = 0;
    pkt_buf->in_intf    = NULL;
    pkt_buf->out_intf   = NULL;
}

static inline bool pkt_buffer_has_short_rx_len(pkt_buffer_t *pkt_buf, uint16_t len)
{
    return (pkt_buf->offset + len) > pkt_buf->rx_len;
}

static inline void pkt_buffer_set_egress_intf_self(pkt_buffer_t *pkt_buf)
{
    pkt_buf->out_intf = pkt_buf->in_intf;
}

static inline void pkt_buffer_set_tx_len_default(pkt_buffer_t *pkt_buf)
{
    pkt_buf->tx_len = pkt_buf->offset;
}

void pkt_buffer_initialize(pkt_buffer_t *pkt_buf);

void pkt_buffer_ref_count_up(pkt_buffer_t *pkt_buf);

void pkt_buffer_ref_count_down(pkt_buffer_t *pkt_buf);

bool pkt_buffer_rx_frame_in_range(pkt_buffer_t *pkt_buf, uint32_t hdr_len);

void pkt_buffer_decode_byte(pkt_buffer_t *pkt_buf, uint8_t *u8);

void pkt_buffer_decode_2_bytes(pkt_buffer_t *pkt_buf, uint16_t *u16);

void pkt_buffer_decode_4_bytes(pkt_buffer_t *pkt_buf, uint32_t *u32);

void pkt_buffer_decode_bytes(pkt_buffer_t *pkt_buf, uint8_t *data, uint32_t data_len);

void pkt_buffer_encode_byte(pkt_buffer_t *pkt_buf, uint8_t u8);

void pkt_buffer_encode_2_bytes(pkt_buffer_t *pkt_buf, uint16_t u16);

void pkt_buffer_encode_4_bytes(pkt_buffer_t *pkt_buf, uint32_t u32);

void pkt_buffer_encode_bytes(pkt_buffer_t *pkt_buf, uint8_t *data, uint32_t data_len);

#endif

