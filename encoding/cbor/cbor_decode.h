#ifndef ENCODING_CBOR_DECODE_H
#define ENCODING_CBOR_DECODE_H

namespace netos {

/**
 * @brief - Implements CBOR decoder.
 */
class cbor_decode {
    public:
        /**
         * @brief - Constructor.
         * @param [in] buf - pointer to the buffer.
         * @param [in] len - length of the buffer.
         */
        cbor_decode(uint8_t *buf, uint32_t len);

        /**
         * @brief - Destructor.
         */
        ~cbor_decode();

        /**
         * @brief - Check if the simple value is true.
         * @param [in] val - simple value.
         * @return - true if the simple value is true.
         */
        bool is_simple_value_true(uint32_t val);

        /**
         * @brief - Check if the simple value is false.
         * @param [in] val - simple value.
         * @return - true if the simple value is false.
         */
        bool is_simple_value_false(uint32_t val);

        /**
         * @brief - Check if the simple value is null.
         * @param [in] val - simple value.
         * @return - true if the simple value is null.
         */
        bool is_simple_value_null(uint32_t val);

        /**
         * @brief - Decode the type and length of the next element.
         * @param [out] type - type of the element.
         * @param [out] len - length of the element.
         */
        void decode_type_len(uint32_t *type, uint32_t *len);

        /**
         * @brief - Decode an unsigned integer.
         * @param [in] len - length of the unsigned integer.
         * @return - unsigned integer.
         */
        uint32_t decode_uint(uint32_t len);

        /**
         * @brief - Decode a byte string.
         * @param [out] byte_string - array of bytes.
         * @param [in] len - length of the byte string.
         */
        void decode_byte_string(uint8_t *byte_string, uint32_t len);

        /**
         * @brief - Decode a string.
         * @param [in] len - length of the string.
         * @return - string.
         */
        std::string decode_str(uint32_t len);

        /**
         * @brief - Get the remaining length of the buffer.
         * @return - remaining length of the buffer.
         */
        uint32_t remaining_len() { return this->buf_len_ - this->offset_; }

    private:
        void copy_bytes(uint8_t *buf, uint32_t buf_len);
        void copy_string(std::string &str, uint32_t len);

        uint8_t *buf_;
        uint32_t buf_len_;
        uint32_t offset_;
};

}

#endif
