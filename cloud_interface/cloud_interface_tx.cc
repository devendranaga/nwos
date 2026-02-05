#include "cloud_interface.h"
#include "cloud_interface_tx.h"

namespace netos {

netos_status cloud_interface_tx::initialize(const char *ipaddr, uint32_t port)
{
    this->client_sock_ = std::make_shared<udp_client_socket>();

    this->server_addr_.sin_family = AF_INET;
    this->server_addr_.sin_port = htons(port);
    this->server_addr_.sin_addr.s_addr = inet_addr(ipaddr);
    
    return netos_status::NETOS_STATUS_SUCCESS;
}

}
