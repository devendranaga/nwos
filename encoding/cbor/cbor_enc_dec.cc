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
    if (val <= 23) {
        this->encode_uint8(val);
    }
}

void cbor_encode::encode_uint8(uint32_t val)
{
    ENCODE_HEADER_BYTE(this->buf_, this->offset_, CBOR_MAJOR_TYPE_UINT, val);
}

void cbor_encode::encode_str(const std::string &str)
{
    if (str.size() <= 23) {
        this->encode_str8(str);
    }
}

void cbor_encode::encode_str8(const std::string &str)
{
    uint32_t i;

    ENCODE_HEADER_BYTE(this->buf_, this->offset_, CBOR_MAJOR_TYPE_TEXT, str.size());

    for (i = 0; i < str.size(); i ++) {
        this->buf_[this->offset_ + i] = str[i];
    }

    this->offset_ += str.size();
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
        return len;
    }

    return val;
}

std::string cbor_decode::decode_str(uint32_t len)
{
    std::string str;

    for (uint32_t i = 0; i < len; i ++) {
        str += this->buf_[this->offset_ + i];
    }

    this->offset_ += len;

    return str;
}

}

