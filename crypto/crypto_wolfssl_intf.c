#include "crypto_intf.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static void *netos_wolfssl_init_gmac()
{
    Aes *aes;
    int ret;

    aes = calloc(1, sizeof(Aes));
    if (!aes) {
        return NULL;
    }

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        goto err;
    }

    return aes;

err:
    free(aes);
    return NULL;
}

static netos_status_t netos_wolfssl_set_gmac_key(void *ctx, netos_crypto_key_t *key)
{
    Aes *aes = ctx;
    int ret;

    ret = wc_AesGcmSetKey(aes, key->key, key->key_len);
    if (ret != 0) {
        return NETOS_STATUS_CRYPTO_WOLFSSL_KEY_SET_FAILURE;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_wolfssl_generate_gmac(void *ctx, netos_crypto_aes_gmac_params_t *params)
{
    Aes *aes = ctx;
    int ret;

    ret = wc_AesGcmEncrypt(aes,
                           NULL,
                           NULL,
                           0,
                           params->iv,
                           NETOS_CRYPTO_IV_LEN_DEFAULT,
                           params->tag,
                           NETOS_CRYPTO_TAG_LEN_DEFAULT,
                           params->aad,
                           params->aad_len);
    if (ret != 0) {
        return NETOS_STATUS_CRYPTO_WOLFSSL_GMAC_GEN_FAILURE;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_wolfssl_verify_gmac(void *ctx, netos_crypto_aes_gmac_params_t *params)
{
    Aes *aes = ctx;
    int ret;

    ret = wc_AesGcmDecrypt(aes,
                           NULL,
                           NULL,
                           0,
                           params->iv,
                           NETOS_CRYPTO_IV_LEN_DEFAULT,
                           params->tag,
                           NETOS_CRYPTO_TAG_LEN_DEFAULT,
                           params->aad,
                           params->aad_len);
    if (ret != 0) {
        return NETOS_STATUS_CRYPTO_WOLFSSL_GMAC_VERIFY_FAILURE;
    }

    return NETOS_STATUS_SUCCESS;
}

static void netos_wolfssl_deinit_gmac(void *ctx)
{
    Aes *aes = ctx;

    if (aes) {
        free(aes);
    }
}

static const netos_crypto_intf_t wolfssl_crypto_intf = {
    .init_gmac      = netos_wolfssl_init_gmac,
    .set_gmac_key   = netos_wolfssl_set_gmac_key,
    .generate_gmac  = netos_wolfssl_generate_gmac,
    .verify_gmac    = netos_wolfssl_verify_gmac,
    .deinit_gmac    = netos_wolfssl_deinit_gmac
};

const netos_crypto_intf_t *netos_crypto_intf_get_instance()
{
    return &wolfssl_crypto_intf;
}

