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

netos_crypto_ctx_t *netos_crypto_ctx_initialize();

void *netos_crypto_init_gmac(netos_crypto_ctx_t *ctx);

netos_status_t
netos_crypto_set_gmac_key(netos_crypto_ctx_t *ctx,
                          void *gmac_ctx,
                          netos_crypto_key_t *key);

netos_status_t
netos_crypto_generate_gmac(netos_crypto_ctx_t *ctx,
                           void *gmac_ctx,
                           netos_crypto_aes_gmac_params_t *params);

netos_status_t
netos_crypto_verify_gmac(netos_crypto_ctx_t *ctx,
                         void *gmac_ctx,
                         netos_crypto_aes_gmac_params_t *params);

void netos_crypto_deinit_gmac(netos_crypto_ctx_t *ctx, void *gmac_ctx);

#if defined(__cplusplus)
}
#endif

#endif

