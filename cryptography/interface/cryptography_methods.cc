#include <openssl/evp.h>

#include <cryptography_methods.h>
#include <cryptography_hash.h>
#include <cryptography_aes_gcm.h>
#include <openssl_hash.h>
#include <wolfssl_gcm.h>

namespace netos {

std::shared_ptr<cryptography_hash>
cryptography_methods::get_hash_instance(crypto_provider provider)
{
    switch (provider) {
        case crypto_provider::OPENSSL:
            return std::make_shared<openssl_hash>();
        default:
            return nullptr;
    }
}

std::shared_ptr<cryptography_aes_gcm>
cryptography_methods::get_aes_gcm_instance(crypto_provider provider)
{
    switch (provider) {
        case crypto_provider::WOLFSSL:
            return std::make_shared<wolfssl_aes_gcm>();
        default:
            return nullptr;
    }
}

std::shared_ptr<cryptography_aes_gmac>
cryptography_methods::get_aes_gmac_instance(crypto_provider provider)
{
    switch (provider) {
        case crypto_provider::WOLFSSL:
            return std::make_shared<wolfssl_aes_gmac>();
        default:
            return nullptr;
    }
}

}
