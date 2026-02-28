#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "packet_buf.h"

namespace netos {

netos_status packet_buf_pool::initialize(uint32_t size)
{
    uint32_t i;

    this->size_ = size;
    this->head_ = nullptr;

    for (i = 0; i < size; i ++) {
        packet_buf *pkt_buf;

        pkt_buf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pkt_buf) {
            return netos_status::NETOS_STATUS_ALLOC_FAILURE;
        }

        pkt_buf->allocate();
        if (!this->head_) {
            this->head_ = pkt_buf;
        } else {
            pkt_buf->next = this->head_;
            this->head_ = pkt_buf;
        }
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

packet_buf *packet_buf_pool::get_pkt()
{
    std::unique_lock<std::mutex> l(this->lock_);

    if (this->head_) {
        packet_buf *pkt = this->head_;
        this->head_ = this->head_->next;

        pkt->offset_ = 0;
        pkt->len_ = 0;

        return pkt;
    }
    return nullptr;
}

void packet_buf_pool::put_pkt(packet_buf *pkt)
{
    pkt->offset_ = 0;
    pkt->len_ = 0;

    std::unique_lock<std::mutex> l(this->lock_);
    pkt->next = this->head_;
    this->head_ = pkt;
}

netos_status packet_buf::allocate()
{
    this->buf_ = (uint8_t *)calloc(1, NETOS_PACKET_BUF_SIZE);
    if (!this->buf_) {
        return netos_status::NETOS_STATUS_ALLOC_FAILURE;
    }
    this->len_ = NETOS_PACKET_BUF_SIZE;
    this->offset_ = 0;

    return netos_status::NETOS_STATUS_SUCCESS;
}

void packet_buf::free_ptr()
{
    if (this->buf_) {
        free(this->buf_);
    }
    this->len_ = 0;
    this->offset_ = 0;
}

void packet_buf::serialize_bit(uint8_t bit_pos)
{
    this->buf_[this->offset_] |= (1 << bit_pos);
}

void packet_buf::serialize_byte(uint8_t val)
{
    this->buf_[this->offset_] = val;
    this->offset_ ++;
}

void packet_buf::serialize_bytes(uint8_t *bytes, uint32_t len)
{
    memcpy(this->buf_ + this->offset_, bytes, len);
    this->offset_ += len;
}

void packet_buf::serialize_mac(uint8_t *mac)
{
    this->serialize_bytes(mac, NETOS_MACADDR_LEN);
}

void packet_buf::serialize_2_bytes(uint16_t val)
{
    this->buf_[this->offset_] = (val & 0xFF00) >> 8;
    this->buf_[this->offset_ + 1] = (val & 0x00FF);
    this->offset_ += 2;
}

void packet_buf::serialize_4_bytes(uint32_t val)
{
    this->buf_[this->offset_] = (val & 0xFF000000) >> 24;
    this->buf_[this->offset_ + 1] = (val & 0x00FF0000) >> 16;
    this->buf_[this->offset_ + 2] = (val & 0x0000FF00) >> 8;
    this->buf_[this->offset_ + 3] = (val & 0x000000FF);
    this->offset_ += 4;
}

void packet_buf::serialize_8_bytes(uint64_t val)
{
    this->buf_[this->offset_]       = (val & 0xFF00000000000000) >> 56;
    this->buf_[this->offset_ + 1]   = (val & 0x00FF000000000000) >> 48;
    this->buf_[this->offset_ + 2]   = (val & 0x0000FF0000000000) >> 40;
    this->buf_[this->offset_ + 3]   = (val & 0x000000FF00000000) >> 32;
    this->buf_[this->offset_ + 4]   = (val & 0x00000000FF000000) >> 24;
    this->buf_[this->offset_ + 5]   = (val & 0x0000000000FF0000) >> 16;
    this->buf_[this->offset_ + 6]   = (val & 0x000000000000FF00) >> 8;
    this->buf_[this->offset_ + 7]   = (val & 0x00000000000000FF);
    this->offset_ += 8;
}

void packet_buf::deserialize_byte(uint8_t *val)
{
    if ((this->offset_ + sizeof(uint8_t)) > this->len_) {
        return;
    }

    *val = this->buf_[this->offset_];

    this->offset_ ++;
}

void packet_buf::deserialize_bytes(uint8_t *bytes, uint32_t len)
{
    if ((this->offset_ + len) > this->len_) {
        return;
    }

    memcpy(bytes, this->buf_ + this->offset_, len);

    this->offset_ += len;
}

void packet_buf::deserialize_mac(uint8_t *mac)
{
    this->deserialize_bytes(mac, NETOS_MACADDR_LEN);
}

void packet_buf::deserialize_2_bytes(uint16_t *val)
{
    if ((this->offset_ + sizeof(uint16_t)) > this->len_) {
        return;
    }

    *val = ((this->buf_[this->offset_] << 8) | this->buf_[this->offset_ + 1]);
    this->offset_ += 2;
}

void packet_buf::deserialize_4_bytes(uint32_t *val)
{
    if ((this->offset_ + sizeof(uint32_t)) > this->len_) {
        return;
    }

    *val = ((this->buf_[this->offset_] << 24) |
            (this->buf_[this->offset_ + 1] << 16) |
            (this->buf_[this->offset_ + 2] << 8) |
            (this->buf_[this->offset_ + 3]));
    this->offset_ += 4;
}

void packet_buf::deserialize_8_bytes(uint64_t *val)
{
    if ((this->offset_ + sizeof(uint64_t)) > this->len_) {
        return;
    }

    *val = (((uint64_t)(this->buf_[this->offset_]) << 56) |
            ((uint64_t)(this->buf_[this->offset_ + 1]) << 48) |
            ((uint64_t)(this->buf_[this->offset_ + 2]) << 40) |
            ((uint64_t)(this->buf_[this->offset_ + 3]) << 32) |
            (this->buf_[this->offset_ + 4] << 24) |
            (this->buf_[this->offset_ + 5] << 16) |
            (this->buf_[this->offset_ + 6] << 8) |
            this->buf_[this->offset_ + 7]);
    this->offset_ += 8;
}

uint32_t packet_buf::get_remaining_len()
{
    return this->len_ - this->offset_;
}

uint8_t *packet_buf::get_raw_buf() const
{
    return this->buf_;
}

uint32_t packet_buf::get_raw_buf_len() const
{
    return this->offset_;
}

}
