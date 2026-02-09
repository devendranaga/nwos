#include <stdio.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <cryptography_hash.h>
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

const EVP_MD *get_crypto_digest_ctx(uint32_t crypto_digest)
{
    switch (crypto_digest) {
        case CRYPTO_HASH_SHA256:
            return EVP_sha256();
        case CRYPTO_HASH_SHA384:
            return EVP_sha384();
        case CRYPTO_HASH_SHA512:
            return EVP_sha512();
        default:
            return nullptr;
    }
}

netos_status openssl_rsa::sign_privkey(const std::string &privkey,
                                       cryptography_rsa_params *params)
{
    FILE *fp;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;
    int ret;

    md = get_crypto_digest_ctx(params->crypto_digest);
    if (!md) {
        return NETOS_STATUS_CRYPTO_INVAL_DIGEST;
    }

    fp = fopen(privkey.c_str(), "rb");
    if (!fp) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!pkey) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    fclose(fp);

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, pkey);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = EVP_DigestSignUpdate(md_ctx, params->data_in, params->data_in_len);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    params->signature_len = CRYPTOGRAPHY_RSA_SIGNATURE_LEN;
    ret = EVP_DigestSignFinal(md_ctx, params->signature, &params->signature_len);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return NETOS_STATUS_SUCCESS;
}

netos_status openssl_rsa::verify_pubkey(const std::string &pubkey,
                                       cryptography_rsa_params *params)
{
    FILE *fp;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;
    int ret;

    md = get_crypto_digest_ctx(params->crypto_digest);
    if (!md) {
        return NETOS_STATUS_CRYPTO_INVAL_DIGEST;
    }

    fp = fopen(pubkey.c_str(), "rb");
    if (!fp) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (!pkey) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    fclose(fp);

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = EVP_DigestVerifyInit(md_ctx, &pkey_ctx, md, NULL, pkey);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = EVP_DigestVerifyUpdate(md_ctx, params->data_in, params->data_in_len);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    ret = EVP_DigestVerifyFinal(md_ctx, params->signature, params->signature_len);
    if (ret != 1) {
        return NETOS_STATUS_CRYPTO_PKEY_GEN_ERROR;
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return NETOS_STATUS_SUCCESS;
}

}
