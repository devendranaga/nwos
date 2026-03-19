#ifndef NETOS_CLOUD_INTERFACE_TX_H
#define NETOS_CLOUD_INTERFACE_TX_H

#include <netinet/in.h>

#include <memory>
#include "udp_socket.h"
#include "error_codes.h"
#include "gcd.h"
#include "stats_interface_tx.h"

using namespace netos::lib;

namespace netos {

class cloud_interface_tx {
    public:
        explicit cloud_interface_tx() { }
        ~cloud_interface_tx() { }

        netos_status initialize();

    private:
        void netos_cloud_intf_stats_send_timer();
        netos_status send_tx_stats();
        std::shared_ptr<udp_client_socket> client_sock_;
        struct sockaddr_in server_addr_;
};

}

#endif

