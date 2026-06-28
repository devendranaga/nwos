#ifndef NETOS_CRYPTO_AES_GMAC_H
#define NETOS_CRYPTO_AES_GMAC_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include "netos_status.h"

#define NETOS_CRYPTO_KEY_LEN_MAX        32
#define NETOS_CRYPTO_IV_LEN_DEFAULT     12
#define NETOS_CRYPTO_TAG_LEN_DEFAULT    16

typedef struct {
    uint8_t     key[NETOS_CRYPTO_KEY_LEN_MAX];
    uint32_t    key_len;
} netos_crypto_key_t;

typedef struct {
    uint8_t     *aad;
    uint32_t    aad_len;
    uint8_t     *iv;
    uint8_t     *tag;
} netos_crypto_aes_gmac_params_t;

typedef struct {
    // GMAC params
    void            *(*init_gmac)(void);
    netos_status_t  (*set_gmac_key)(void *ctx, netos_crypto_key_t *key);
    netos_status_t  (*generate_gmac)(void *ctx, netos_crypto_aes_gmac_params_t *params);
    netos_status_t  (*verify_gmac)(void *ctx, netos_crypto_aes_gmac_params_t *params);
    void            (*deinit_gmac)(void *ctx);
} netos_crypto_intf_t;

#if defined(__cplusplus)
}
#endif

#endif

