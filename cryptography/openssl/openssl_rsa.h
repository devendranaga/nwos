#ifndef CRYPTOGRAPHY_OPENSSL_OPENSSL_RSA_H
#define CRYPTOGRAPHY_OPENSSL_OPENSSL_RSA_H

#include "error_codes.h"
#include "cryptography_rsa.h"

using namespace netos::lib;

namespace netos {

class openssl_rsa : public cryptography_rsa {
    public:
        explicit openssl_rsa();
        ~openssl_rsa();

        netos_status gen_keypair(rsa_key_type key_type,
                                 const std::string &pkey,
                                 const std::string &pubkey);
    private:
};

}

#endif
