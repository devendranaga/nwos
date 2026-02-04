#ifndef CRYPTOGRAPHY_SRV_H
#define CRYPTOGRAPHY_SRV_H

#include "udp_socket.h"

using namespace netos::lib;

namespace netos {

class cryptography_srv {
    public:
        explicit cryptography_srv();
        ~cryptography_srv();

        void run(int argc, char **argv);
    private:
        void receive_callback(int fd);

        std::string config_ipaddr_;
        uint32_t config_port_;
        std::shared_ptr<udp_server_socket> udp_srv_;
};

}

#endif
