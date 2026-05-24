#ifndef WOLFSSL_GCM_H
#define WOLFSSL_GCM_H

#define HAVE_AESGCM 1

#include <iostream>
#include <wolfssl/wolfcrypt/aes.h>
#include "cryptography_aes_gcm.h"

namespace netos {

using namespace netos::lib;

class wolfssl_aes_gcm : public cryptography_aes_gcm {
    public:
        explicit wolfssl_aes_gcm() = default;
        ~wolfssl_aes_gcm() = default;

        netos_status init();

        netos_status set_key(const uint8_t *key, uint32_t key_len);

        netos_status encrypt(const uint8_t *key,
                             uint32_t key_len,
                             cryptography_aes_gcm_params *gcm_params);

        netos_status decrypt(const uint8_t *key,
                             uint32_t key_len,
                             cryptography_aes_gcm_params *gcm_params);

        netos_status deinit();

    private:
        Aes wolfssl_aes_gcm_ctx_;
};

class wolfssl_aes_gmac : public cryptography_aes_gmac {
    public:
        explicit wolfssl_aes_gmac() = default;
        ~wolfssl_aes_gmac() = default;

        netos_status init();

        netos_status set_key(const uint8_t *key, uint32_t key_len);

        netos_status generate_mac(const uint8_t *key,
                                  uint32_t key_len,
                                  cryptography_aes_gcm_params *gcm_params);

        netos_status verify_mac(const uint8_t *key,
                                uint32_t key_len,
                                cryptography_aes_gcm_params *gcm_params);

        netos_status deinit();
};

}

#endif
