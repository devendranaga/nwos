#include <stdint.h>
#include <stdlib.h>
#include "crypto_ctx.h"
#include "crypto_intf.h"
#include "crypto_wolfssl_intf.h"

netos_crypto_ctx_t *netos_crypto_ctx_initialize()
{
    netos_crypto_ctx_t *crypto_ctx;

    crypto_ctx = calloc(1, sizeof(netos_crypto_ctx_t));
    if (!crypto_ctx) {
        return NULL;
    }

    crypto_ctx->crypto_intf = netos_crypto_intf_get_instance();
    if (!crypto_ctx->crypto_intf) {
        goto end;
    }

    return crypto_ctx;

end:
    if (crypto_ctx) {
        free(crypto_ctx);
    }
    return NULL;
}

void *netos_crypto_init_gmac(netos_crypto_ctx_t *ctx)
{
    const netos_crypto_intf_t *crypto_intf = ctx->crypto_intf;

    return crypto_intf->init_gmac();
}

netos_status_t netos_crypto_set_gmac_key(netos_crypto_ctx_t *ctx, void *gmac_ctx, netos_crypto_key_t *key)
{
    const netos_crypto_intf_t *crypto_intf = ctx->crypto_intf;

    return crypto_intf->set_gmac_key(gmac_ctx, key);
}

netos_status_t netos_crypto_generate_gmac(netos_crypto_ctx_t *ctx, void *gmac_ctx, netos_crypto_aes_gmac_params_t *params)
{
    const netos_crypto_intf_t *crypto_intf = ctx->crypto_intf;

    return crypto_intf->generate_gmac(gmac_ctx, params);
}

netos_status_t netos_crypto_verify_gmac(netos_crypto_ctx_t *ctx, void *gmac_ctx, netos_crypto_aes_gmac_params_t *params)
{
    const netos_crypto_intf_t *crypto_intf = ctx->crypto_intf;

    return crypto_intf->verify_gmac(gmac_ctx, params);
}

void netos_crypto_deinit_gmac(netos_crypto_ctx_t *ctx, void *gmac_ctx)
{
    const netos_crypto_intf_t *crypto_intf = ctx->crypto_intf;

    return crypto_intf->deinit_gmac(gmac_ctx);
}

