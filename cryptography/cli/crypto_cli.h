#ifndef CRYPTO_CLI_H
#define CRYPTO_CLI_H

#include <stdint.h>
#include <string>

namespace netos {

class crypto_command_parser {
    public:
        crypto_command_parser() { }
        ~crypto_command_parser() { }

        void parse(std::vector<std::string> &tokens, char *msg, uint32_t len);
};

class crypto_command_handler {
    public:
        crypto_command_handler() { }
        ~crypto_command_handler() { }

        void handle(std::vector<std::string> &tokens);

    private:
        void handle_hash_fn(std::vector<std::string> &tokens);
};

class crypto_cli {
    public:
        crypto_cli();
        ~crypto_cli();

        void run(int argc, char **argv);

    private:
        crypto_command_parser parser_;
        std::string config_ipaddr_;
        uint32_t config_port_;
};

}

#endif
