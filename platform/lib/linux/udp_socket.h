#ifndef PLATFORM_LINUX_UDP_SOCKET_H
#define PLATFORM_LINUX_UDP_SOCKET_H

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "udp_socket.h"

namespace netos {

namespace lib {

/**
 * @brief - UDP server socket class
 *          Provides the interface to instantiate a udp serer and
 *          provides helpers to send and receive UDP frames.
 */
class udp_server_socket {
    public:
        /**
         * @brief - Initialize the UDP server socket.
         *
         * @param ip - IP address to bind the socket to.
         * @param port - Port number to bind the socket to.
         */
        udp_server_socket(const char *ip, uint16_t port);

        /**
         * @brief - Cleanup the server.
         */
        ~udp_server_socket();

        /**
         * @brief - Receive a UDP frame.
         *
         * @param buf - Buffer to store the received frame.
         * @param len - Length of the buffer.
         * @param addr - Address of the sender will be copied here.
         * @return ssize_t - Number of bytes received.
         */
        ssize_t udp_recv_from(void *buf, size_t len, struct sockaddr_in *addr);

        /**
         * @brief - Send a UDP frame.
         *
         * @param buf - Buffer containing the frame to send.
         * @param len - Length of the buffer.
         * @param addr - Address of the receiver needs to be copied by the caller.
         * @return ssize_t - Number of bytes sent.
         */
        ssize_t udp_send_to(const void *buf, size_t len, struct sockaddr_in *addr);

    private:
        int fd_;
};

}

}

#endif
