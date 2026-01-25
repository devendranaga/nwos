#ifndef CRYPTOGRAPHY_INTERFACE_CRYPTOGRAPHY_METHODS_H
#define CRYPTOGRAPHY_INTERFACE_CRYPTOGRAPHY_METHODS_H

#include <memory>

#include <cryptography_hash.h>

namespace netos {

enum class crypto_provider {
    OPENSSL,
};

class cryptography_methods {
    public:
        static cryptography_methods* get_instance(crypto_provider provider)
        {
            static cryptography_methods methods;
            return &methods;
        }
        ~cryptography_methods() = default;

        std::shared_ptr<cryptography_hash> get_hash_instance(crypto_provider provider);

    private:
        explicit cryptography_methods() = default;
};

}

#endif
