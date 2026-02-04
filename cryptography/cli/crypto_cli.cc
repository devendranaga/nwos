#include <stdio.h>
#include <getopt.h>
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
        char user_input[1024];

        printf("crypto_cli> ");
        fflush(stdout);
        if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
            continue;
        }
    }
}

}

int main(int argc, char **argv)
{
    netos::crypto_cli cli;

    cli.run(argc, argv);

    return 0;
}
