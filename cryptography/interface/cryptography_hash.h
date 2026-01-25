#ifndef CRYPTOGRAPHY_INTERFACE_CRYPTOGRAPHY_HASH_H
#define CRYPTOGRAPHY_INTERFACE_CRYPTOGRAPHY_HASH_H

#include "error_codes.h"

#define CRYPTOGRAPHY_HASH_LEN 64

using namespace netos::lib;

namespace netos {

struct cryptograpy_hash_params {
    uint8_t *data_in;
    uint32_t data_in_len;
    uint8_t hash[CRYPTOGRAPHY_HASH_LEN];
    uint32_t hash_len;

    explicit cryptograpy_hash_params() : data_in(nullptr), data_in_len(0), hash_len(0) {}
};

class cryptography_hash {
    public:
        explicit cryptography_hash() = default;
        virtual ~cryptography_hash() = default;

        virtual netos_status sha256(cryptograpy_hash_params *params) = 0;
        virtual netos_status sha384(cryptograpy_hash_params *params) = 0;
        virtual netos_status sha512(cryptograpy_hash_params *params) = 0;
        virtual netos_status sha3_256(cryptograpy_hash_params *params) = 0;
        virtual netos_status sha3_384(cryptograpy_hash_params *params) = 0;
        virtual netos_status sha3_512(cryptograpy_hash_params *params) = 0;
};

}

#endif
