#ifndef CRYPTOGRAPHY_INTERFACE_RSA_H
#define CRYPTOGRAPHY_INTERFACE_RSA_H

#include <string>

#include "error_codes.h"

using namespace netos::lib;

namespace netos {

#define CRYPTOGRAPHY_RSA_SIGNATURE_LEN 256

/**
 * @brief - RSA key types.
 */
enum class rsa_key_type : uint32_t {
    RSA_KEY_TYPE_2048 = 1,
    RSA_KEY_TYPE_3072,
    RSA_KEY_TYPE_4096,
};

/**
 * @brief - Defines RSA params.
 */
struct cryptography_rsa_params {
    /* Type of cryptography digest: SHA2, SHA3 .. */
    uint32_t    crypto_digest;

    /* input data and data length. */
    uint8_t     *data_in;
    size_t      data_in_len;

    /**
     * output signature and signature length.
     * becomes input in case of verify.
     */
    uint8_t     signature[CRYPTOGRAPHY_RSA_SIGNATURE_LEN];
    size_t      signature_len;

    explicit cryptography_rsa_params() :
                crypto_digest(0),
                data_in(nullptr),
                data_in_len(0),
                signature_len(0) {}
    ~cryptography_rsa_params() = default;
};

/**
 * @brief - Defines the RSA interface.
 */
class cryptography_rsa {
    public:
        explicit cryptography_rsa() = default;
        virtual ~cryptography_rsa() = default;

        /**
         * @brief - Generate RSA key pair. (pub and private key)
         *
         * @param [in] key_type - lengths of keys.
         * @param [in] pkey - private key.
         * @param [in] pubkey - public key.
         *
         * @return returns netos_status codes.
         */
        virtual netos_status gen_keypair(rsa_key_type key_type,
                                         const std::string &pkey,
                                         const std::string &pubkey) = 0;

        /**
         * @brief - Sign the message using the private key.
         *
         * @param [in] privkey - private key.
         * @param [inout] params - cryptopgraphy params (output is in signature parameter).
         *
         * @return returns netos_status codes.
         */
        virtual netos_status sign_privkey(const std::string &privkey,
                                          cryptography_rsa_params *params) = 0;

        /**
         * @brief - Verify the mesasge using the private key.
         *
         * @param [in] pubkey - public key.
         * @param [in] params - cryptography params.
         *
         * @return returns netos_status codes.
         */
        virtual netos_status verify_pubkey(const std::string &pubkey,
                                           cryptography_rsa_params *params) = 0;
    private:
};

}

#endif

