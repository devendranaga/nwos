#define HAVE_AESGCM 1

#include "cryptography_aes_params.h"
#include "wolfssl_gcm.h"

namespace netos {

netos_status wolfssl_aes_gcm::init()
{
    int ret;

    // heap = nullptr
    // dev_id = -1 invalid dev id
    ret = wc_AesInit(&this->wolfssl_aes_gcm_ctx_, nullptr, -1);
    if (ret != 0) {
        return netos_status::NETOS_STATUS_CRYPTO_WOLFSSL_GCM_INIT_FAILED;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gcm::set_key(const uint8_t *key, uint32_t key_len)
{
    int ret;

    ret = wc_AesGcmSetKey(&this->wolfssl_aes_gcm_ctx_, key, key_len);
    if (ret != 0) {
        return netos_status::NETOS_STATUS_CRYPTO_WOLFSSL_GCM_SET_KEY_FAILED;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gcm::encrypt(const uint8_t *key,
                                      uint32_t key_len,
                                      cryptography_aes_gcm_params *gcm_params)
{
    int ret;

    ret = wc_AesGcmEncrypt(&this->wolfssl_aes_gcm_ctx_,
                           gcm_params->ciphertext,
                           gcm_params->plaintext,
                           gcm_params->plaintext_len,
                           gcm_params->iv,
                           CRYPTOGRAPHY_AES_IV_LEN,
                           gcm_params->tag,
                           CRYPTOGRAPHY_AES_TAG_LEN,
                           gcm_params->aad,
                           gcm_params->aad_len);
    if (ret != 0) {
        return netos_status::NETOS_STATUS_CRYPTO_WOLFSSL_GCM_ENCRYPT_FAILED;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gcm::decrypt(const uint8_t *key,
                                      uint32_t key_len,
                                      cryptography_aes_gcm_params *gcm_params)
{
    int ret;

    ret = wc_AesGcmDecrypt(&this->wolfssl_aes_gcm_ctx_,
                           gcm_params->ciphertext,
                           gcm_params->plaintext,
                           gcm_params->plaintext_len,
                           gcm_params->iv,
                           CRYPTOGRAPHY_AES_IV_LEN,
                           gcm_params->tag,
                           CRYPTOGRAPHY_AES_TAG_LEN,
                           gcm_params->aad,
                           gcm_params->aad_len);
    if (ret != 0) {
        return netos_status::NETOS_STATUS_CRYPTO_WOLFSSL_GCM_DECRYPT_FAILED;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gcm::deinit()
{
    wc_AesFree(&this->wolfssl_aes_gcm_ctx_);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gmac::init()
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gmac::set_key(const uint8_t *key, uint32_t key_len)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gmac::generate_mac(const uint8_t *key,
                                            uint32_t key_len,
                                            cryptography_aes_gcm_params *gmac_params)
{
    int ret;

    ret = wc_Gmac(key,
                  key_len,
                  gmac_params->iv,
                  CRYPTOGRAPHY_AES_IV_LEN,
                  gmac_params->aad,
                  gmac_params->aad_len,
                  gmac_params->tag,
                  CRYPTOGRAPHY_AES_TAG_LEN,
                  nullptr);
    if (ret != 0) {
        return netos_status::NETOS_STATUS_CRYPTO_WOLFSSL_GMAC_GEN_TAG_FAILED;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gmac::verify_mac(const uint8_t *key,
                                          uint32_t key_len,
                                          cryptography_aes_gcm_params *gmac_params)
{
    int ret;

    ret = wc_GmacVerify(key,
                        key_len,
                        gmac_params->iv,
                        CRYPTOGRAPHY_AES_IV_LEN,
                        gmac_params->aad,
                        gmac_params->aad_len,
                        gmac_params->tag,
                        CRYPTOGRAPHY_AES_TAG_LEN);
    if (ret != 0) {
        return netos_status::NETOS_STATUS_CRYPTO_WOLFSSL_GMAC_VER_TAG_FAILED;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status wolfssl_aes_gmac::deinit()
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

}
