#include <iostream>
#include <stdint.h>

#include <openssl/evp.h>

#include "error_codes.h"
#include "openssl_hash.h"

namespace netos {

netos_status openssl_hash::sha256(cryptograpy_hash_params *params)
{
    return this->hash_msg(EVP_sha256(), params);
}

netos_status openssl_hash::sha384(cryptograpy_hash_params *params)
{
    return this->hash_msg(EVP_sha384(), params);
}

netos_status openssl_hash::sha512(cryptograpy_hash_params *params)
{
    return this->hash_msg(EVP_sha512(), params);
}

netos_status openssl_hash::sha3_256(cryptograpy_hash_params *params)
{
    return this->hash_msg(EVP_sha3_256(), params);
}

netos_status openssl_hash::sha3_384(cryptograpy_hash_params *params)
{
    return this->hash_msg(EVP_sha3_384(), params);
}

netos_status openssl_hash::sha3_512(cryptograpy_hash_params *params)
{
    return this->hash_msg(EVP_sha3_512(), params);
}

netos_status openssl_hash::hash_msg(const EVP_MD *md, cryptograpy_hash_params *params)
{
    EVP_MD_CTX *md_ctx;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return netos_status::NETOS_STATUS_ALLOC_FAILURE;
    }

    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1) {
        return netos_status::NETOS_STATUS_GENERIC_ERROR;
    }

    if (EVP_DigestUpdate(md_ctx, params->data_in, params->data_in_len) != 1) {
        return netos_status::NETOS_STATUS_GENERIC_ERROR;
    }

    if (EVP_DigestFinal_ex(md_ctx, params->hash, &params->hash_len) != 1) {
        return netos_status::NETOS_STATUS_GENERIC_ERROR;
    }

    EVP_MD_CTX_free(md_ctx);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}
