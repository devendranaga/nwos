#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include "pkt_buffer.h"
#include "event_info.h"

void pkt_buffer_initialize(pkt_buffer_t *pkt_buf)
{
    pkt_buf->offset     = 0;
    pkt_buf->rx_len     = 0;
    pkt_buf->tx_len     = 0;
    pkt_buf->ref_count  = 0;
    pthread_mutex_init(&pkt_buf->lock, NULL);
    NETOS_EVENT_INIT(pkt_buf->event_type, pkt_buf->event_desc);
}

void pkt_buffer_ref_count_up(pkt_buffer_t *pkt_buf)
{
    pthread_mutex_lock(&pkt_buf->lock);
    pkt_buf->ref_count ++;
    pthread_mutex_unlock(&pkt_buf->lock);
}

void pkt_buffer_ref_count_up_n(pkt_buffer_t *pkt_buf, uint32_t count)
{
    pthread_mutex_lock(&pkt_buf->lock);
    pkt_buf->ref_count += 2;
    pthread_mutex_unlock(&pkt_buf->lock);
}

void pkt_buffer_ref_count_down(pkt_buffer_t *pkt_buf)
{
    pthread_mutex_lock(&pkt_buf->lock);
    if (pkt_buf->ref_count > 0) {
        pkt_buf->ref_count --;
    }
    pthread_mutex_unlock(&pkt_buf->lock);
}

bool pkt_buffer_rx_frame_in_range(pkt_buffer_t *pkt_buf, uint32_t hdr_len)
{
    return (pkt_buf->rx_len >= (pkt_buf->offset + hdr_len));
}

void pkt_buffer_decode_byte(pkt_buffer_t *pkt_buf, uint8_t *u8)
{
    *u8 = pkt_buf->buffer[pkt_buf->offset];
    pkt_buf->offset ++;
}

void pkt_buffer_encode_byte(pkt_buffer_t *pkt_buf, uint8_t u8)
{
    pkt_buf->buffer[pkt_buf->offset] = u8;
    pkt_buf->offset ++;
}

void pkt_buffer_decode_2_bytes(pkt_buffer_t *pkt_buf, uint16_t *u16)
{
    uint8_t *buf = pkt_buf->buffer;
    uint32_t offset = pkt_buf->offset;

    *u16 = (buf[offset] << 8) | (buf[offset + 1]);
    pkt_buf->offset += 2;
}

void pkt_buffer_encode_2_bytes(pkt_buffer_t *pkt_buf, uint16_t u16)
{
    pkt_buf->buffer[pkt_buf->offset] = (u16 & 0xFF00) >> 8;
    pkt_buf->buffer[pkt_buf->offset + 1] = (u16 & 0x00FF);
    pkt_buf->offset += 2;
}

void pkt_buffer_decode_4_bytes(pkt_buffer_t *pkt_buf, uint32_t *u32)
{
    uint8_t *buf = pkt_buf->buffer;
    uint32_t offset = pkt_buf->offset;

    *u32 = (buf[offset] << 24) | (buf[offset + 1] << 16) |
           (buf[offset + 2] << 8) | (buf[offset + 3]);
    pkt_buf->offset += 4u;
}

void pkt_buffer_encode_4_bytes(pkt_buffer_t *pkt_buf, uint32_t u32)
{
    pkt_buf->buffer[pkt_buf->offset] = (u32 & 0xFF000000) >> 24;
    pkt_buf->buffer[pkt_buf->offset + 1] = (u32 & 0x00FF0000) >> 16;
    pkt_buf->buffer[pkt_buf->offset + 2] = (u32 & 0x0000FF00) >> 8;
    pkt_buf->buffer[pkt_buf->offset + 3] = (u32 & 0x000000FF);
    pkt_buf->offset += 4;
}

void pkt_buffer_decode_bytes(pkt_buffer_t *pkt_buf, uint8_t *data, uint32_t data_len)
{
    memcpy(data, &pkt_buf->buffer[pkt_buf->offset], data_len);
    pkt_buf->offset += data_len;
}

void pkt_buffer_encode_bytes(pkt_buffer_t *pkt_buf, uint8_t *data, uint32_t data_len)
{
    memcpy(&pkt_buf->buffer[pkt_buf->offset], data, data_len);
    pkt_buf->offset += data_len;
}

