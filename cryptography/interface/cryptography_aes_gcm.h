#ifndef CRYPTOGRAPHY_INTERFACE_AES_GCM_H
#define CRYPTOGRAPHY_INTERFACE_AES_GCM_H

#include <stdint.h>
#include "error_codes.h"

namespace netos {

using namespace netos::lib;

struct cryptography_aes_gcm_params {
    uint8_t     *aad;
    uint32_t    aad_len;
    uint8_t     *iv;
    uint8_t     *plaintext;
    uint32_t    plaintext_len;
    uint8_t     *ciphertext;
    uint32_t    ciphertext_len;
    uint8_t     *tag;
};

class cryptography_aes_gcm {
    public:
        explicit cryptography_aes_gcm() = default;
        virtual ~cryptography_aes_gcm() = default;

        virtual netos_status init() = 0;

        virtual netos_status set_key(const uint8_t *key, uint32_t key_len) = 0;

        virtual netos_status encrypt(const uint8_t *key,
                                     uint32_t key_len,
                                     cryptography_aes_gcm_params *gcm_params) = 0;

        virtual netos_status decrypt(const uint8_t *key,
                                     uint32_t key_len,
                                     cryptography_aes_gcm_params *gcm_params) = 0;

        virtual netos_status deinit() = 0;
};

class cryptography_aes_gmac {
    public:
        explicit cryptography_aes_gmac() = default;
        virtual ~cryptography_aes_gmac() = default;

        virtual netos_status init() = 0;

        virtual netos_status set_key(const uint8_t *key, uint32_t key_len) = 0;

        virtual netos_status generate_mac(const uint8_t *key,
                                          uint32_t key_len,
                                          cryptography_aes_gcm_params *gcm_params) = 0;

        virtual netos_status verify_mac(const uint8_t *key,
                                        uint32_t key_len,
                                        cryptography_aes_gcm_params *gcm_params) = 0;

        virtual netos_status deinit() = 0;
};

}

#endif
