#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <functional>
#include <system_error>

#include "logger.h"

namespace netos {

namespace logging {

void usage(const char *progname)
{
    fprintf(stderr, "%s -i <ipaddr> -p <port>\n", progname);
}

logger::logger(int argc, char **argv)
{
    int ret;

    // parse command line arguments
    while ((ret = getopt(argc, argv, "i:p:")) != -1) {
        switch (ret) {
            case 'i':
                this->config_server_ip_ = strdup(optarg);
            break;
            case 'p':
                this->config_server_port_ = std::stoi(optarg);
            break;
            default:
                usage(argv[0]);
                return;
        }
    }

    // create a server socket
    this->server_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (this->server_fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to socket");
    }

    uint32_t reuse_addr = 1;
    ret = setsockopt(this->server_fd_,
                     SOL_SOCKET,
                     SO_REUSEADDR,
                     &reuse_addr,
                     sizeof(reuse_addr));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to setsockopt");
    }

    struct sockaddr_in serv;
    serv.sin_addr.s_addr = inet_addr(this->config_server_ip_);
    serv.sin_port = htons(this->config_server_port_);
    serv.sin_family = AF_INET;
    ret = bind(this->server_fd_, (struct sockaddr *)&serv, sizeof(serv));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to bind");
    }

    // create a thread that receives the log messages
    auto f1 = std::bind(&logger::rx_thread, this);
    this->rx_thread_ = std::make_shared<std::thread>(f1);

    this->initialized_ = true;
}

void logger::rx_thread()
{
    int ret;

    while (1) {
    }
}

logger::~logger()
{
}

void logger::run()
{
    if (!this->initialized_) {
        return;
    }

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

}

}

int main(int argc, char **argv)
{
    netos::logging::logger l(argc, argv);

    l.run();

    return 0;
}

