/**
 * @brief - Implements Raw Socket.
 * 
 * @copyright - All rights reserved. Devendra Naga.
*/
#include <iostream>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <raw_socket.h>

#define ERR_ON_SYSCALL(__res, __match, __str) { \
    if (__res < __match) { \
        throw std::runtime_error(__str); \
    } \
}

namespace netos {

namespace lib {

raw_socket::raw_socket(const std::string devname, uint16_t ethertype):
                                  dev_(devname)
{
    int ret;

    if (devname.size() >= IFNAMSIZ - 1) {
        throw std::runtime_error("interface name too long");
    }

    fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    ERR_ON_SYSCALL(fd_, 0, "failed to socket");

    struct ifreq req;

    // get interface flags for promisc
    std::memset(&req, 0, sizeof(struct ifreq));
    strncpy(req.ifr_name, devname.c_str(), IFNAMSIZ - 1);
    req.ifr_name[IFNAMSIZ - 1] = '\0';
    ret = ioctl(fd_, SIOCGIFFLAGS, &req);
    ERR_ON_SYSCALL(ret, 0, "failed to SIOCGIFFLAGS");

    // set promisc
    req.ifr_flags |= IFF_PROMISC;
    ret = ioctl(fd_, SIOCSIFFLAGS, &req);
    ERR_ON_SYSCALL(ret, 0, "failed to SIOCSIFFLAGS");

    // get hardware address for transmit packet
    std::memset(&req, 0, sizeof(struct ifreq));
    strncpy(req.ifr_name, devname.c_str(), IFNAMSIZ - 1);
    req.ifr_name[IFNAMSIZ - 1] = '\0';
    ret = ioctl(fd_, SIOCGIFHWADDR, &req);
    ERR_ON_SYSCALL(ret, 0, "failed to SIOCGIFHWADDR");

    devmac_[0] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[0];
    devmac_[1] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[1];
    devmac_[2] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[2];
    devmac_[3] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[3];
    devmac_[4] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[4];
    devmac_[5] = ((uint8_t *)&req.ifr_hwaddr.sa_data)[5];

    std::memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, devname.c_str(), IFNAMSIZ - 1);
    req.ifr_name[IFNAMSIZ - 1] = '\0';
    ret = ioctl(fd_, SIOCGIFINDEX, &req);
    if (ret < 0) {
        throw std::runtime_error("failed to get interface index");
    }
    ERR_ON_SYSCALL(ret, 0, "failed to get interface index");

    // bind to device name
    ret = setsockopt(fd_, SOL_SOCKET, SO_BINDTODEVICE, &req, sizeof(req));
    if (ret < 0) {
        throw std::runtime_error("failed to bind to device");
    }

    ERR_ON_SYSCALL(ret, 0, "failed to SO_BINDTODEVICE");
    ifindex_ = req.ifr_ifindex;

    struct sockaddr_ll lladdr;

    // the bind is required to receive packets to and from the specific interface
    //
    // without this the packets will be received from every single interface
    std::memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_ifindex = req.ifr_ifindex;
    lladdr.sll_protocol = htons(ETH_P_ALL);
    lladdr.sll_family = AF_PACKET;

    ret = bind(fd_, (struct sockaddr *)&lladdr, sizeof(lladdr));
    ERR_ON_SYSCALL(ret, 0, "failed to bind in");
}

raw_socket::~raw_socket() 
{
    if (fd_ > 0) {
        int ret;
        struct ifreq req;

        // get  promisc
        std::memset(&req, 0, sizeof(struct ifreq));
        strncpy(req.ifr_name, dev_.c_str(), IFNAMSIZ - 1);
        req.ifr_name[IFNAMSIZ - 1] = '\0';
        ret = ioctl(fd_, SIOCGIFFLAGS, &req);
        if (ret < 0) {
            return;
        }

        // disable promisc
        req.ifr_flags ^= IFF_PROMISC;
        ret = ioctl(fd_, SIOCSIFFLAGS, &req);
        if (ret < 0) {
            return;
        }

        close(fd_);
        fd_ = -1;
    }
}

int raw_socket::get_socket() const noexcept
{
    return fd_;
}

int raw_socket::send_msg(const uint8_t *mac, uint16_t ethertype, uint8_t *data, size_t data_len) noexcept
{
    struct sockaddr_ll lladdr;
    struct ether_header *eth;
    char txbuf[1500];
    int txlen = sizeof(*eth);

    std::memset(txbuf, 0, sizeof(txbuf));

    eth = (struct ether_header *) txbuf;
    eth->ether_shost[0] = devmac_[0];
    eth->ether_shost[1] = devmac_[1];
    eth->ether_shost[2] = devmac_[2];
    eth->ether_shost[3] = devmac_[3];
    eth->ether_shost[4] = devmac_[4];
    eth->ether_shost[5] = devmac_[5];

    eth->ether_dhost[0] = mac[0];
    eth->ether_dhost[1] = mac[1];
    eth->ether_dhost[2] = mac[2];
    eth->ether_dhost[3] = mac[3];
    eth->ether_dhost[4] = mac[4];
    eth->ether_dhost[5] = mac[5];

    eth->ether_type = htons(ethertype);

    std::memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_ifindex = ifindex_;
    lladdr.sll_halen = ETH_ALEN;
    lladdr.sll_addr[0] = mac[0];
    lladdr.sll_addr[1] = mac[1];
    lladdr.sll_addr[2] = mac[2];
    lladdr.sll_addr[3] = mac[3];
    lladdr.sll_addr[4] = mac[4];
    lladdr.sll_addr[5] = mac[5];

    /* Out of bounds check. */
    if (data_len > (sizeof(txbuf) - sizeof(*eth))) {
        return -1;
    }

    memcpy(txbuf + txlen, data, data_len);

    return sendto(fd_, txbuf, txlen + data_len, 0, (struct sockaddr *) &lladdr, sizeof(struct sockaddr_ll));
}


int raw_socket::send_msg(const uint8_t *target, uint8_t *data, size_t data_len) noexcept
{
    struct sockaddr_ll lladdr;

    lladdr.sll_ifindex = ifindex_;
    lladdr.sll_halen = ETH_ALEN;
    lladdr.sll_addr[0] = target[0];
    lladdr.sll_addr[1] = target[1];
    lladdr.sll_addr[2] = target[2];
    lladdr.sll_addr[3] = target[3];
    lladdr.sll_addr[4] = target[4];
    lladdr.sll_addr[5] = target[5];

    return sendto(fd_, data, data_len, 0, (struct sockaddr *)&lladdr, sizeof(struct sockaddr_ll));
}

static int __recv_msg(int fd, uint8_t *mac, uint8_t *data, size_t data_size)
{
    int ret;
    struct sockaddr_ll lladdr;
    socklen_t len = sizeof(struct sockaddr_ll);

    ret = recvfrom(fd, data, data_size, 0, (struct sockaddr *)&lladdr, &len);
    if (ret < 0) {
        return -1;
    }

    if (mac) {
        mac[0] = lladdr.sll_addr[0];
        mac[1] = lladdr.sll_addr[1];
        mac[2] = lladdr.sll_addr[2];
        mac[3] = lladdr.sll_addr[3];
        mac[4] = lladdr.sll_addr[4];
        mac[5] = lladdr.sll_addr[5];
    }

    return ret;

}

int raw_socket::recv_msg(uint8_t *mac, uint8_t *data, size_t data_size) noexcept
{
    return __recv_msg(fd_, mac, data, data_size);
}

int raw_socket::recv_msg(uint8_t *data, size_t data_size) noexcept
{
    return __recv_msg(fd_, nullptr, data, data_size);
}

}

}

