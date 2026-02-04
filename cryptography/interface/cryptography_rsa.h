#ifndef CRYPTOGRAPHY_INTERFACE_RSA_H
#define CRYPTOGRAPHY_INTERFACE_RSA_H

#include <string>

#include "error_codes.h"

using namespace netos::lib;

namespace netos {

enum class rsa_key_type : uint32_t {
    RSA_KEY_TYPE_2048 = 1,
    RSA_KEY_TYPE_3072,
    RSA_KEY_TYPE_4096,
};

class cryptography_rsa {
    public:
        explicit cryptography_rsa() = default;
        virtual ~cryptography_rsa() = default;

        virtual netos_status gen_keypair(rsa_key_type key_type,
                                         const std::string &pkey,
                                         const std::string &pubkey) = 0;
    private:
};

}
#endif
