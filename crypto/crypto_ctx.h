#ifndef NETOS_CRYPTO_CTX_H
#define NETOS_CRYPTO_CTX_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include "crypto_intf.h"

typedef struct {
    const void *crypto_intf;
} netos_crypto_ctx_t;

/**
 * @brief - initialize the crypto context and return it.
 */
netos_crypto_ctx_t *netos_crypto_ctx_initialize();

/**
 * @brief - initialize the GMAC context to operate on GMAC.
 *
 * @param [in] ctx - crypto context.
 *
 * @return returns gmac_ctx on success and NULL pointer on failure.
 */
void *netos_crypto_init_gmac(netos_crypto_ctx_t *ctx);

/**
 * @brief - Set the GMAC keys.
 *
 * @param [in] ctx - crypto context.
 * @param [in] gmac_ctx - GMAC context.
 * @param [in] key - Crypto key.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t
netos_crypto_set_gmac_key(netos_crypto_ctx_t *ctx,
                          void *gmac_ctx,
                          netos_crypto_key_t *key);

/**
 * @brief - Generate the GMAC.
 *
 * @param [in] ctx - crypto context.
 * @param [in] gmac_ctx - GMAC context.
 * @param [in] params - GMAC params.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t
netos_crypto_generate_gmac(netos_crypto_ctx_t *ctx,
                           void *gmac_ctx,
                           netos_crypto_aes_gmac_params_t *params);

netos_status_t
netos_crypto_verify_gmac(netos_crypto_ctx_t *ctx,
                         void *gmac_ctx,
                         netos_crypto_aes_gmac_params_t *params);

void netos_crypto_deinit_gmac(netos_crypto_ctx_t *ctx, void *gmac_ctx);

void *netos_crypto_init_gcm(netos_crypto_ctx_t *ctx);

netos_status_t netos_crypto_set_gcm_key(netos_crypto_ctx_t *ctx, void *gcm_ctx, netos_crypto_key_t *key);

netos_status_t netos_crypto_encrypt_gcm(netos_crypto_ctx_t *ctx, void *gcm_ctx, netos_crypto_aes_gcm_params_t *params);

netos_status_t netos_crypto_decrypt_gcm(netos_crypto_ctx_t *ctx, void *gcm_ctx, netos_crypto_aes_gcm_params_t *params);

void netos_crypto_deinit_gcm(netos_crypto_ctx_t *ctx, void *gcm_ctx);

#if defined(__cplusplus)
}
#endif

#endif

