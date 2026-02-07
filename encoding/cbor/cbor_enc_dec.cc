#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <stdexcept>
#include <exception>

#include "cbor_types.h"
#include "cbor_encode.h"
#include "cbor_decode.h"

#define ENCODE_HEADER_BYTE(__buffer, __offset, __major_type, __val) {\
    __buffer[__offset] = ((__major_type) << 5);\
    __buffer[__offset] |= (__val);\
    __offset ++;\
}

namespace netos {

cbor_encode::cbor_encode(uint32_t len)
{
    this->buf_ = (uint8_t *)calloc(1, len);
    if (!this->buf_) {
        throw std::runtime_error("cannot allocate buffer");
    }

    this->offset_ = 0;
    this->buf_len_ = len;
    this->preallocated_ = true;
}

cbor_encode::cbor_encode(uint8_t *buf, uint32_t len)
{
    this->buf_ = buf;
    this->buf_len_ = len;
    this->offset_ = 0;
    this->preallocated_ = false;
}

cbor_encode::~cbor_encode()
{
    if (this->buf_ && this->preallocated_) {
        free(this->buf_);
    }
}

void cbor_encode::encode_uint(uint32_t val)
{
    /**
     * Below 23, the additional data is the value.
     */
    if (val <= 23) {
        ENCODE_HEADER_BYTE(this->buf_, this->offset_, CBOR_MAJOR_TYPE_UINT, val);

    } else if ((val > 23) && (val <= 255)) {
        this->buf_[this->offset_] = 0x18;
        this->buf_[this->offset_ + 1] = val;

        this->offset_ += 2;

    } else if ((val > 255) && (val <= 65535)) {
        this->buf_[this->offset_] = 0x19;
        this->buf_[this->offset_ + 1] = (val & 0xFF00) >> 8;
        this->buf_[this->offset_ + 2] = (val & 0x00FF);

        this->offset_ += 3;

    } else {
        this->buf_[this->offset_] = 0x1A;
        this->buf_[this->offset_ + 1] = (val & 0xFF000000) >> 24;
        this->buf_[this->offset_ + 2] = (val & 0x00FF0000) >> 16;
        this->buf_[this->offset_ + 3] = (val & 0x0000FF00) >> 8;
        this->buf_[this->offset_ + 4] = (val & 0x000000FF);

        this->offset_ += 5;

    }
}

void cbor_encode::encode_byte_string(uint8_t *byte_string, uint32_t len)
{
    uint32_t i = 0;

    if (len <= 23) {
        ENCODE_HEADER_BYTE(this->buf_, this->offset_, CBOR_MAJOR_TYPE_BSTR, len);
        for (i = 0; i < len; i ++) {
            this->buf_[this->offset_] = byte_string[i];
            this->offset_ ++;
        }
    } else if ((len > 23) && (len <= 255)) {
        this->buf_[this->offset_] = (CBOR_MAJOR_TYPE_BSTR << 5);
        this->buf_[this->offset_] |= 0x18;
        this->buf_[this->offset_ + 1] = len;
        this->offset_ += 2;

        for (i = 0; i < len; i ++) {
            this->buf_[this->offset_] = byte_string[i];
            this->offset_ ++;
        }
    } else if ((len > 255) && (len <= 65535)) {
        this->buf_[this->offset_] = (CBOR_MAJOR_TYPE_BSTR << 5);
        this->buf_[this->offset_] |= 0x19;
        this->buf_[this->offset_ + 1] = (len & 0xFF00) >> 8;
        this->buf_[this->offset_ + 2] = (len & 0x00FF);
        this->offset_ += 3;

        for (i = 0; i < len; i ++) {
            this->buf_[this->offset_] = byte_string[i];
            this->offset_ ++;
        }
    } else if (len > 65535) {
        this->buf_[this->offset_] = (CBOR_MAJOR_TYPE_BSTR << 5);
        this->buf_[this->offset_] |= 0x1A;
        this->buf_[this->offset_ + 1] = (len & 0xFF000000) >> 24;
        this->buf_[this->offset_ + 2] = (len & 0x00FF0000) >> 16;
        this->buf_[this->offset_ + 3] = (len & 0x0000FF00) >> 8;
        this->buf_[this->offset_ + 4] = (len & 0x000000FF);
        this->offset_ += 5;

        for (i = 0; i < len; i ++) {
            this->buf_[this->offset_] = byte_string[i];
            this->offset_ ++;
        }
    }
}

void cbor_encode::encode_string_full(const std::string &str)
{
    uint32_t i;

    for (i = 0; i < str.size(); i ++) {
        this->buf_[this->offset_ + i] = str[i];
    }

    this->offset_ += str.size();
}

void cbor_encode::encode_str(const std::string &str)
{
    uint32_t val = str.size();

    if (val <= 23) {
        ENCODE_HEADER_BYTE(this->buf_, this->offset_, CBOR_MAJOR_TYPE_TEXT, str.size());

        this->encode_string_full(str);

    } else if ((val > 23) && (val <= 255)) {
        this->buf_[this->offset_] = (CBOR_MAJOR_TYPE_TEXT << 5);
        this->buf_[this->offset_] |= 0x18;
        this->buf_[this->offset_ + 1] = val;
        this->offset_ += 2;

        this->encode_string_full(str);

    } else if ((val > 255) && (val <= 65535)) {
        this->buf_[this->offset_] = (CBOR_MAJOR_TYPE_TEXT << 5);
        this->buf_[this->offset_] |= 0x19;
        this->buf_[this->offset_ + 1] = (val & 0xFF00) >> 8;
        this->buf_[this->offset_ + 2] = (val & 0x00FF);
        this->offset_ += 3;

        this->encode_string_full(str);

    } else if (val > 65535) {
        this->buf_[this->offset_] = (CBOR_MAJOR_TYPE_TEXT << 5);
        this->buf_[this->offset_] |= 0x1A;
        this->buf_[this->offset_ + 1] = (val & 0xFF000000) >> 24;
        this->buf_[this->offset_ + 2] = (val & 0x00FF0000) >> 16;
        this->buf_[this->offset_ + 3] = (val & 0x0000FF00) >> 8;
        this->buf_[this->offset_ + 4] = (val & 0x000000FF);
        this->offset_ += 5;

        this->encode_string_full(str);
    }
}

void cbor_encode::encode_array(uint32_t len)
{
    if (len <= 23) {
        this->encode_array8(len);
    }
}

void cbor_encode::encode_array8(uint32_t len)
{
    ENCODE_HEADER_BYTE(this->buf_, this->offset_, CBOR_MAJOR_TYPE_ARRAY, len);
}

void cbor_encode::encode_map(uint32_t n_elements)
{
    if (n_elements <= 23) {
        this->encode_map8(n_elements);
    }
}

void cbor_encode::encode_map8(uint32_t n_elements)
{
    ENCODE_HEADER_BYTE(this->buf_, this->offset_, CBOR_MAJOR_TYPE_MAP, n_elements);
}

cbor_decode::cbor_decode(uint8_t *buf, uint32_t len)
{
    this->buf_ = buf;
    this->buf_len_ = len;
    this->offset_ = 0;
}

cbor_decode::~cbor_decode()
{
}

void cbor_decode::decode_type_len(uint32_t *type, uint32_t *len)
{
    *type = this->buf_[this->offset_] >> 5;
    *len = this->buf_[this->offset_] & 0x1f;

    this->offset_ ++;
}

uint32_t cbor_decode::decode_uint(uint32_t len)
{
    uint32_t val = 0;

    if (len <= 23) {
        val = len;

    } else if ((len > 23) && (len <= 255)) {
        if (len == 0x18) {
            val = this->buf_[this->offset_];
            this->offset_ ++;

        } else if (len == 0x19) {
            val = (this->buf_[this->offset_] << 8) | this->buf_[this->offset_];
            this->offset_ += 2;

        } else if (len == 0x1A) {
            val = (this->buf_[this->offset_] << 24) | (this->buf_[this->offset_ + 1] << 16) |
                  (this->buf_[this->offset_ + 2] << 8) | this->buf_[this->offset_ + 3];
            this->offset_ += 4;

        }
    }

    return val;
}

void cbor_decode::copy_bytes(uint8_t *buf, uint32_t buf_len)
{
    uint32_t i;

    for (i = 0; i < buf_len; i ++) {
        buf[i] = this->buf_[this->offset_ + i];
    }

    this->offset_ += buf_len;
}

void cbor_decode::decode_byte_string(uint8_t *byte_string, uint32_t len)
{
    uint32_t val = 0;

    val = (len & 0x1f);

    if (len <= 23) {
        this->copy_bytes(byte_string, len);

    } else if (val == 0x18) {
        len = this->buf_[this->offset_];
        this->offset_ ++;

        this->copy_bytes(byte_string, len);

    } else if (val == 0x19) {
        len = (this->buf_[this->offset_] << 8) | this->buf_[this->offset_ + 1];
        this->offset_ += 2;

        this->copy_bytes(byte_string, len);

    } else if (val == 0x1A) {
        len = (this->buf_[this->offset_] << 24) | (this->buf_[this->offset_ + 1] << 16) |
              (this->buf_[this->offset_ + 2] << 8) | this->buf_[this->offset_ + 3];
        this->offset_ += 4;

        this->copy_bytes(byte_string, len);
    }
}

std::string cbor_decode::decode_str(uint32_t len)
{
    std::string str;
    uint32_t val = 0;
    uint32_t len_bytes = 0;

    val = (len & 0x1f);

    if (len <= 23) {
        for (uint32_t i = 0; i < len; i ++) {
            str += this->buf_[this->offset_ + i];
        }

        this->offset_ += len;

    } else if (val == 0x18) {
        len_bytes = this->buf_[this->offset_];
        this->offset_ ++;

        for (uint32_t i = 0; i < len_bytes; i ++) {
            str += this->buf_[this->offset_ + i];
        }

        this->offset_ += len_bytes;

    } else if (val == 0x19) {
        len_bytes = (this->buf_[this->offset_] << 8) | this->buf_[this->offset_ + 1];
        this->offset_ += 2;

        for (uint32_t i = 0; i < len_bytes; i ++) {
            str += this->buf_[this->offset_ + i];
        }

        this->offset_ += len_bytes;

    } else if (val == 0x1A) {
        len_bytes = (this->buf_[this->offset_] << 24) | (this->buf_[this->offset_ + 1] << 16) |
                    (this->buf_[this->offset_ + 2] << 8) | this->buf_[this->offset_ + 3];
        this->offset_ += 4;

        for (uint32_t i = 0; i < len_bytes; i ++) {
            str += this->buf_[this->offset_ + i];
        }

        this->offset_ += len_bytes;

    }

    return str;
}

}

