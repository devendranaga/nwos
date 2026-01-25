#include <openssl/evp.h>

#include <cryptography_methods.h>
#include <cryptography_hash.h>
#include <openssl_hash.h>

namespace netos {

std::shared_ptr<cryptography_hash> cryptography_methods::get_hash_instance(crypto_provider provider)
{
    switch (provider) {
        case crypto_provider::OPENSSL:
            return std::make_shared<openssl_hash>();
        default:
            return nullptr;
    }
}

}
