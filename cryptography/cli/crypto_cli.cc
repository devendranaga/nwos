#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <vector>
#include "crypto_srv_interface.h"
#include "crypto_cli.h"

namespace netos {

crypto_cli::crypto_cli()
{

}

crypto_cli::~crypto_cli()
{

}

void crypto_cli::run(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "i:p:")) != -1) {
        switch (ret) {
            case 'i':
                this->config_ipaddr_ = optarg;
            break;
            case 'p':
                this->config_port_ = std::stoi(optarg);
            break;
            default:
            break;
        }
    }

    while (1) {
        std::vector<std::string> tokens;
        char user_input[1024];

        printf("crypto_cli> ");
        fflush(stdout);
        if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
            continue;
        }

        auto len = strlen(user_input);
        if (user_input[len - 1] == '\n') {
            user_input[len - 1] = '\0';
        }
        this->parser_.parse(tokens, user_input, len - 1);
    }
}

void crypto_command_parser::parse(std::vector<std::string> &tokens, char *msg, uint32_t len)
{
    char token[64] = {0};
    uint32_t i;
    uint32_t j;

    for (i = 0, j = 0; i < len; i ++) {

        if (msg[i] == ' ' || msg[i] == '\0') {
            token[j] = '\0';
            tokens.push_back(token);
            j = 0;
        } else {
            token[j] = msg[i];
            j ++;
        }
    }

    if (i == len) {
        token[j] = '\0';
        tokens.push_back(token);
    }
}

void crypto_command_handler::handle(std::vector<std::string> &tokens)
{
    if (tokens.empty()) {
        return;
    }

    if (tokens[0] == "hash") {
        this->handle_hash_fn(tokens);
    }
}

void crypto_command_handler::handle_hash_fn(std::vector<std::string> &tokens)
{
    if (tokens.size() < 3) {
        return;
    }

    if (tokens[1] == "sha256") {
        
    }
}

}

int main(int argc, char **argv)
{
    netos::crypto_cli cli;

    cli.run(argc, argv);

    return 0;
}
