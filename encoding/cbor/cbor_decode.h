#ifndef ENCODING_CBOR_DECODE_H
#define ENCODING_CBOR_DECODE_H

namespace netos {

class cbor_decode {
    public:
        cbor_decode(uint8_t *buf, uint32_t len);
        ~cbor_decode();

        void decode_type_len(uint32_t *type, uint32_t *len);
        uint32_t decode_uint(uint32_t len);
        std::string decode_str(uint32_t len);
        uint32_t remaining_len() { return this->buf_len_ - this->offset_; }

    private:
        uint8_t *buf_;
        uint32_t buf_len_;
        uint32_t offset_;
};

}

#endif
