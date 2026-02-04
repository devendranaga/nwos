#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <cryptography_rsa.h>
#include <openssl_rsa.h>

namespace netos {

netos_status openssl_rsa::gen_keypair(rsa_key_type key_type,
                                      const std::string &pkey,
                                      const std::string &pubkey)
{
    EVP_PKEY_CTX *evp_ctx;
    uint32_t rsa_key_size = 0;
    int ret;

    switch (key_type) {
        case rsa_key_type::RSA_KEY_TYPE_2048:
            rsa_key_size = 2048;
            break;
        case rsa_key_type::RSA_KEY_TYPE_3072:
            rsa_key_size = 3072;
            break;
        case rsa_key_type::RSA_KEY_TYPE_4096:
            rsa_key_size = 4096;
            break;
        default:
            return NETOS_STATUS_CRYPTO_INVAL_RSA_KEY_LEN;
    }

    evp_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (evp_ctx == NULL) {
        return NETOS_STATUS_CRYPTO_PKEY_CTX_ERROR;
    }

    ret = EVP_PKEY_keygen_init(evp_ctx);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = EVP_PKEY_CTX_set_rsa_keygen_bits(evp_ctx, rsa_key_size);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    EVP_PKEY *pkey_ctx;
    ret = EVP_PKEY_keygen(evp_ctx, &pkey_ctx);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    FILE *fp;

    fp = fopen(pkey.c_str(), "wb");
    if (fp == NULL) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = PEM_write_PrivateKey(fp, pkey_ctx, NULL, NULL, 0, NULL, NULL);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    fflush(fp);
    fclose(fp);

    fp = fopen(pubkey.c_str(), "wb");
    if (fp == NULL) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = PEM_write_PUBKEY(fp, pkey_ctx);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    fflush(fp);
    fclose(fp);

    return NETOS_STATUS_SUCCESS;
}

}
