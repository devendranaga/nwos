#ifndef IDS_PACKET_BUF_H
#define IDS_PACKET_BUF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ids_macro_defs.h"
#include "error_codes.h"

namespace netos {

namespace ids {

#define IDS_PKTBUF_SIZE 4096

using namespace netos::lib;
struct packet_buf {

    uint8_t *buf_;
    uint32_t offset_;
    uint32_t len_;

    netos_status allocate()
    {
        this->buf_ = (uint8_t *)calloc(1, IDS_PKTBUF_SIZE);
        if (!this->buf_) {
            return netos_status::NETOS_STATUS_ALLOC_FAILURE;
        }
        this->len_ = IDS_PKTBUF_SIZE;
        this->offset_ = 0;

        return netos_status::NETOS_STATUS_SUCCESS;
    }

    void free_ptr()
    {
        if (this->buf_) {
            free(this->buf_);
        }
        this->len_ = 0;
        this->offset_ = 0;
    }

    void serialize_bit(uint8_t bit_pos)
    {
        this->buf_[this->offset_] |= (1 << bit_pos);
    }

    void serialize_byte(uint8_t val)
    {
        if ((this->offset_ + sizeof(uint8_t)) >= this->len_) {
            return;
        }
        this->buf_[this->offset_] = val;
        this->offset_ ++;
    }

    void serialize_bytes(uint8_t *bytes, uint32_t len)
    {
        if ((this->offset_ + len) >= this->len_) {
            return;
        }

        memcpy(this->buf_ + this->offset_, bytes, len);
        this->offset_ += len;
    }

    void serialize_mac(uint8_t *mac)
    {
        this->serialize_bytes(mac, NETOS_IDS_MACADDR_LEN);
    }

    void serialize_2_bytes(uint16_t val)
    {
        this->buf_[this->offset_] = (val & 0xFF00) >> 8;
        this->buf_[this->offset_ + 1] = (val & 0x00FF);
        this->offset_ += 2;
    }

    void serialize_4_bytes(uint32_t val)
    {
        this->buf_[this->offset_] = (val & 0xFF000000) >> 24;
        this->buf_[this->offset_ + 1] = (val & 0x00FF0000) >> 16;
        this->buf_[this->offset_ + 2] = (val & 0x0000FF00) >> 8;
        this->buf_[this->offset_ + 3] = (val & 0x000000FF);
        this->offset_ += 4;
    }

    void deserialize_byte(uint8_t *val)
    {
        if ((this->offset_ + sizeof(uint8_t)) > this->len_) {
            return;
        }

        *val = this->buf_[this->offset_];

        this->offset_ ++;
    }

    void deserialize_bytes(uint8_t *bytes, uint32_t len)
    {
        if ((this->offset_ + len) > this->len_) {
            return;
        }

        memcpy(bytes, this->buf_ + this->offset_, len);

        this->offset_ += len;
    }

    void deserialize_mac(uint8_t *mac)
    {
        this->deserialize_bytes(mac, NETOS_IDS_MACADDR_LEN);
    }

    void deserialize_2_bytes(uint16_t *val)
    {
        if ((this->offset_ + sizeof(uint16_t)) > this->len_) {
            return;
        }

        *val = ((this->buf_[this->offset_] << 8) | this->buf_[this->offset_ + 1]);
    }

    void deserialize_4_bytes(uint32_t *val)
    {
        if ((this->offset_ + sizeof(uint32_t)) > this->len_) {
            return;
        }

        *val = ((this->buf_[this->offset_] << 24) |
                (this->buf_[this->offset_ + 1] << 16) |
                (this->buf_[this->offset_ + 2] << 8) |
                (this->buf_[this->offset_]));
    }
};

}

}

#endif

