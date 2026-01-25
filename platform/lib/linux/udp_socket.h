#ifndef PLATFORM_LINUX_UDP_SOCKET_H
#define PLATFORM_LINUX_UDP_SOCKET_H

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "udp_socket.h"

namespace netos {

namespace lib {

class udp_server_socket {
    public:
        udp_server_socket(const char *ip, uint16_t port);
        ~udp_server_socket();

        ssize_t udp_recv_from(void *buf, size_t len, struct sockaddr_in *addr);
        ssize_t udp_send_to(const void *buf, size_t len, struct sockaddr_in *addr);

    private:
        int fd_;
};

}

}

#endif
