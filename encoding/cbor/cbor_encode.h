#ifndef ENCODING_CBOR_ENCODE_H
#define ENCODING_CBOR_ENCODE_H

#include "cbor_types.h"

namespace netos {

/**
 * @brief CBOR encoding class.
 *
 * This class is used to encode CBOR data.
 */
class cbor_encode {
    public:
        /**
         * Allocate the buffer and initialize the buf_len_ and offset_.
         * Throws when the buffer allocation fails
         */
        cbor_encode(uint32_t len);

        /**
         * Preallocated buffer so we do not have to free. Used for
         * fast responses to encoding when called in hot path.
         */
        cbor_encode(uint8_t *buf, uint32_t len);
        ~cbor_encode();

        /**
         * @brief - Encode a unsigned integer.
         * @param [in] val - unsigned integer.
         */
        void encode_uint(uint32_t val);

        /**
         * @brief - Encode a byte string.
         * @param [in] byte_string - array of bytes.
         * @param [in] len - length of the byte string.
         */
        void encode_byte_string(uint8_t *byte_string, uint32_t len);

        /**
         * @brief - Encode a string.
         * @param [in] str - string.
         */
        void encode_str(const std::string &str);

        /**
         * @brief - Encode a array.
         * @param [in] len - length of the array.
         */
        void encode_array(uint32_t len);

        /**
         * @brief - Encode a map.
         * @param [in] n_elements - number of elements in the map.
         */
        void encode_map(uint32_t n_elements);

        /**
         * @brief - Get the encoded data.
         * @return - pointer to the encoded data.
         */
        uint8_t *get_data() { return this->buf_; }

        /**
         * @brief - Get the length of the encoded data.
         * @return - length of the encoded data.
         */
        uint32_t get_len() { return this->offset_; }

    private:
        void copy_byte_string(uint8_t *buf, uint32_t len);

        /**
         * @brief - Encode a string bytes.
         * @param [in] str - string.
         */
        void encode_string_full(const std::string &str);

        /**
         * @brief - Encode an array <= 23 elements in length.
         * @param [in] len - length of the array.
         */
        void encode_array8(uint32_t len);

        /**
         * @brief - Encode a map <= 23 elements in length.
         * @param [in] n_elements - number of elements in the map.
         */
        void encode_map8(uint32_t n_elements);

        uint8_t *buf_;
        uint32_t buf_len_;
        uint32_t offset_;
        bool preallocated_;
};

}


#endif