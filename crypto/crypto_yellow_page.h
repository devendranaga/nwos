#ifndef NETOS_CRYPTO_YELLOW_PAGE_H
#define NETOS_CRYPTO_YELLOW_PAGE_H

#include "crypto_intf.h"

/**
 * @brief - Defines crypto interface.
 */
typedef struct {
    // GMAC params
    void            *(*init_gmac)(void);
    netos_status_t  (*set_gmac_key)(void *ctx, netos_crypto_key_t *key);
    netos_status_t  (*generate_gmac)(void *ctx, netos_crypto_aes_gmac_params_t *params);
    netos_status_t  (*verify_gmac)(void *ctx, netos_crypto_aes_gmac_params_t *params);
    void            (*deinit_gmac)(void *ctx);

    // GCM params
    void            *(*init_gcm)(void);
    netos_status_t  (*set_gcm_key)(void *ctx, netos_crypto_key_t *key);
    netos_status_t  (*encrypt_gcm)(void *ctx, netos_crypto_aes_gcm_params_t *params);
    netos_status_t  (*decrypt_gcm)(void *ctx, netos_crypto_aes_gcm_params_t *params);
    void            (*deinit_gcm)(void *ctx);
} netos_crypto_intf_t;

#endif

