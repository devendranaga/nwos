#ifndef CRYPTO_CLI_H
#define CRYPTO_CLI_H

#include <stdint.h>
#include <string>

namespace netos {

class crypto_cli {
    public:
        crypto_cli();
        ~crypto_cli();

        void run(int argc, char **argv);

    private:
        std::string config_ipaddr_;
        uint32_t config_port_;
};

}

#endif
