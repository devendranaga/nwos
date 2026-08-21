#ifndef NETOS_CRYPTO_AES_GMAC_H
#define NETOS_CRYPTO_AES_GMAC_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include "netos_status.h"

// macro definitions
#define NETOS_CRYPTO_KEY_LEN_MAX        32
#define NETOS_CRYPTO_IV_LEN_DEFAULT     12
#define NETOS_CRYPTO_TAG_LEN_DEFAULT    16

/**
 * @brief - Defines a crypto key.
 */
typedef struct {
    uint8_t     key[NETOS_CRYPTO_KEY_LEN_MAX];
    uint32_t    key_len; // 16 or 32
} netos_crypto_key_t;

/**
 * @brief - Defines GMAC params.
 */
typedef struct {
    uint8_t     *aad; // input
    uint32_t    aad_len; // input
    uint8_t     *iv; // input
    uint8_t     *tag; // output
} netos_crypto_aes_gmac_params_t;

/**
 * @brief - Defines GCM params.
 */
typedef struct {
    uint8_t     *aad; // input
    uint32_t    aad_len; // input
    uint8_t     *in_msg; // input
    uint32_t    in_msg_len; // input
    uint8_t     *out_msg; // output
    uint32_t    out_msg_len; // output
    uint8_t     *iv; // input
    uint8_t     *tag; // output
} netos_crypto_aes_gcm_params_t;

#if defined(__cplusplus)
}
#endif

#endif

