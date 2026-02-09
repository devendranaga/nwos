#ifndef CRYPTOGRAPHY_INTERFACE_RSA_H
#define CRYPTOGRAPHY_INTERFACE_RSA_H

#include <string>

#include "error_codes.h"

using namespace netos::lib;

namespace netos {

#define CRYPTOGRAPHY_RSA_SIGNATURE_LEN 256

enum class rsa_key_type : uint32_t {
    RSA_KEY_TYPE_2048 = 1,
    RSA_KEY_TYPE_3072,
    RSA_KEY_TYPE_4096,
};

struct cryptography_rsa_params {
    uint32_t    crypto_digest;
    uint8_t     *data_in;
    size_t      data_in_len;
    uint8_t     signature[CRYPTOGRAPHY_RSA_SIGNATURE_LEN];
    size_t      signature_len;

    explicit cryptography_rsa_params() :
                crypto_digest(0),
                data_in(nullptr),
                data_in_len(0),
                signature_len(0) {}
    ~cryptography_rsa_params() = default;
};

class cryptography_rsa {
    public:
        explicit cryptography_rsa() = default;
        virtual ~cryptography_rsa() = default;

        virtual netos_status gen_keypair(rsa_key_type key_type,
                                         const std::string &pkey,
                                         const std::string &pubkey) = 0;

        virtual netos_status sign_privkey(const std::string &privkey,
                                          cryptography_rsa_params *params) = 0;

        virtual netos_status verify_pubkey(const std::string &pubkey,
                                           cryptography_rsa_params *params) = 0;
    private:
};

}
#endif
