#ifndef CRYPTOGRAPHY_INTERFACE_CRYPTOGRAPHY_METHODS_H
#define CRYPTOGRAPHY_INTERFACE_CRYPTOGRAPHY_METHODS_H

#include <memory>

#include <cryptography_hash.h>

namespace netos {

enum class crypto_provider {
    OPENSSL,
    WOLFSSL,
};

/**
 * @brief Cryptography methods class
 *
 * @details This class is a singleton class that provides a common interface
 * for different cryptography methods.
 */
class cryptography_methods {
    public:
        /**
         * @brief Get the instance object
         *
         * @param provider crypto provider (openssl / wolfssl)
         * @return cryptography_methods* pointer to the instance
         */
        static cryptography_methods* get_instance(crypto_provider provider)
        {
            static cryptography_methods methods;
            return &methods;
        }
        ~cryptography_methods() = default;

        /**
         * @brief Get the hash instance object
         *
         * @param provider crypto provider (openssl / wolfssl)
         * @return std::shared_ptr<cryptography_hash>
         */
        std::shared_ptr<cryptography_hash> get_hash_instance(crypto_provider provider);

    private:
        explicit cryptography_methods() = default;
        cryptography_methods(const cryptography_methods&) = delete;
        cryptography_methods& operator=(const cryptography_methods&) = delete;
};

}

#endif
