#ifndef ENCODING_CBOR_ENCODE_H
#define ENCODING_CBOR_ENCODE_H

#include "cbor_types.h"

namespace netos {

class cbor_encode {
    public:
        cbor_encode(uint32_t len);
        ~cbor_encode();

        void encode_uint(uint32_t val);
        void encode_str(const std::string &str);
        void encode_array(uint32_t len);
        void encode_map(uint32_t n_elements);

        uint8_t *get_data() { return this->buf_; }
        uint32_t get_len() { return this->offset_; }

    private:
        void encode_uint8(uint32_t val);
        void encode_str8(const std::string &str);
        void encode_array8(uint32_t len);
        void encode_map8(uint32_t n_elements);

        uint8_t *buf_;
        uint32_t buf_len_;
        uint32_t offset_;
};

}


#endif