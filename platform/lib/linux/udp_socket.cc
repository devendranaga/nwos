#include <socket_helper.h>
#include <udp_socket.h>
#include <system_error>

namespace netos {

namespace lib {

udp_server_socket::udp_server_socket(const char *ipaddr, uint16_t port)
{
    this->fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (this->fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to socket");
    }

    if (set_socket_reuse(this->fd_) < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to reuse socket address");
    }

    struct sockaddr_in addr;
    addr.sin_addr.s_addr = inet_addr(ipaddr);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    int ret = bind(this->fd_, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to bind");
    }
}

udp_server_socket::~udp_server_socket()
{
    if (this->fd_ >= 0) {
        close(this->fd_);
    }
}

ssize_t udp_server_socket::udp_recv_from(void *buf, size_t len, struct sockaddr_in *addr)
{
    socklen_t addr_len = sizeof(struct sockaddr_in);

    return recvfrom(this->fd_, buf, len, 0, (struct sockaddr *)addr, &addr_len);
}

ssize_t udp_server_socket::udp_send_to(const void *buf, size_t len, struct sockaddr_in *addr)
{
    socklen_t addr_len = sizeof(struct sockaddr_in);

    return sendto(this->fd_, buf, len, 0, (struct sockaddr *)addr, addr_len);
}

udp_client_socket::udp_client_socket()
{
    this->fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (this->fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "failed to socket");
    }
}

udp_client_socket::~udp_client_socket()
{
    if (this->fd_ >= 0) {
        close(this->fd_);
    }
}

ssize_t udp_client_socket::udp_send_to(const void *buf, size_t len, struct sockaddr_in *addr)
{
    socklen_t addr_len = sizeof(struct sockaddr_in);

    return sendto(this->fd_, buf, len, 0, (struct sockaddr *)addr, addr_len);
}

ssize_t udp_client_socket::udp_recv_from(void *buf, size_t len, struct sockaddr_in *addr)
{
    socklen_t addr_len = sizeof(struct sockaddr_in);

    return recvfrom(this->fd_, buf, len, 0, (struct sockaddr *)addr, &addr_len);
}

}

}
