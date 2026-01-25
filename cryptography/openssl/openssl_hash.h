#ifndef CRYPTOGRAPHY_OPENSSL_HASH_H
#define CRYPTOGRAPHY_OPENSSL_HASH_H

#include <cryptography_hash.h>

namespace netos {

class openssl_hash : public cryptography_hash {
    public:
        explicit openssl_hash() = default;
        ~openssl_hash() = default;

        netos_status sha256(cryptograpy_hash_params *params);
        netos_status sha384(cryptograpy_hash_params *params);
        netos_status sha512(cryptograpy_hash_params *params);
        netos_status sha3_256(cryptograpy_hash_params *params);
        netos_status sha3_384(cryptograpy_hash_params *params);
        netos_status sha3_512(cryptograpy_hash_params *params);

    private:
        netos_status hash_msg(const EVP_MD *md, cryptograpy_hash_params *params);
};

}

#endif
