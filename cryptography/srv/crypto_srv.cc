#include <iostream>
#include <thread>
#include <memory>
#include <getopt.h>
#include <functional>

#include "gcd.h"
#include "crypto_srv.h"

using namespace netos::lib;

namespace netos {

cryptography_srv::cryptography_srv()
{

}

cryptography_srv::~cryptography_srv()
{

}

void cryptography_srv::termination_handler()
{
    printf("termination handler called\n");
}

void cryptography_srv::run(int argc, char **argv)
{
    gcd *gcd_ctx;
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

    gcd_ctx = gcd::instance();
    gcd_ctx->initialize_thr_pool(4);

    this->udp_srv_ = std::make_shared<udp_server_socket>(this->config_ipaddr_.c_str(),
                                                         this->config_port_);

    socket_callback callback = std::bind(&cryptography_srv::receive_callback,
                                         this,
                                         std::placeholders::_1);
    gcd_ctx->register_socket(this->udp_srv_->get_fd(), callback);

    term_callback term_cb = std::bind(&cryptography_srv::termination_handler,
                                      this);
    gcd_ctx->register_term_signal(term_cb);

    gcd_ctx->run();
}

void cryptography_srv::receive_callback(int fd)
{
    struct sockaddr_in sender_addr;
    char msg[2048];
    int ret;

    ret = this->udp_srv_->udp_recv_from(msg, sizeof(msg), &sender_addr);
    if (ret < 0) {
        return;
    }
}

}

int main(int argc, char **argv)
{
    netos::cryptography_srv csrv;

    csrv.run(argc, argv);
}

