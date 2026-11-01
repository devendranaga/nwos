#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <net/if.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h>
#include "netos_status.h"
#include "net_ioctl.h"
#include "protocol_const.h"

netos_status_t netos_ioctl_set_promisc_fd(int fd, const char *ifname)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_GET_FLAGS_FAILED;
    }

    ifr.ifr_flags |= IFF_PROMISC;

    ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_SET_FLAGS_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ioctl_clear_promisc_fd(int fd, const char *ifname)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_GET_FLAGS_FAILED;
    }

    ifr.ifr_flags &= ~IFF_PROMISC;

    ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_SET_FLAGS_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ioctl_bind_to_device(int fd, const char *ifname)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_BIND_TO_DEVICE_FAILED;
    }

    ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_BIND_TO_DEVICE_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

int netos_ioctl_get_ifindex(int fd, const char *ifname)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFINDEX, &ifr);
    if (ret != 0) {
        return -1;
    }

    return ifr.ifr_ifindex;
}

netos_status_t netos_ioctl_get_macaddr(int fd, const char *ifname, uint8_t *macaddr)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_GET_HWADDR_FAILED;
    }

    memcpy(macaddr, (uint8_t *)(ifr.ifr_hwaddr.sa_data), NETOS_MACADDR_LEN);

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ioctl_get_ipaddr(int fd, const char *ifname, uint32_t *ipaddr)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;

    ret = ioctl(fd, SIOCGIFADDR, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_GET_IPADDR_FAILED;
    }

    struct sockaddr_in *ifaddr = (struct sockaddr_in *)(&ifr.ifr_addr);
    *ipaddr = ntohl(ifaddr->sin_addr.s_addr);

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ioctl_get_mtu(int fd, const char *ifname, uint32_t *mtu)
{
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;

    ret = ioctl(fd, SIOCGIFMTU, &ifr);
    if (ret != 0) {
        return NETOS_STATUS_IOCTL_GET_MTU_FAILED;
    }

    *mtu = ifr.ifr_mtu;
    return NETOS_STATUS_SUCCESS;
}

netos_ctl_ip6addr_t *netos_ioctl_get_ip6addrs(void)
{
    struct ifaddrs *ifaddr, *ifa;
    netos_ctl_ip6addr_t *ip6_addr_head = NULL;
    int ret;

    ret = getifaddrs(&ifaddr);
    if (ret == -1) {
        return NULL;
    }

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            struct in6_addr raw_addr = ipv6->sin6_addr;
            netos_ctl_ip6addr_t *ip6_addr;

            ip6_addr = calloc(1, sizeof(netos_ctl_ip6addr_t));
            if (!ip6_addr) {
                goto end;
            }

            memcpy(ip6_addr->ip6addr, raw_addr.s6_addr, NETOS_IPV6_ADDR_LEN);

            ip6_addr->next = ip6_addr_head;
            ip6_addr_head = ip6_addr;
        }
    }

    freeifaddrs(ifaddr);
    return ip6_addr_head;

end:
    freeifaddrs(ifaddr);
    netos_ioctl_free_ip6addrs(ip6_addr_head);
    return NULL;
}

void netos_ioctl_free_ip6addrs(netos_ctl_ip6addr_t *ip6_addr)
{
    netos_ctl_ip6addr_t *node, *prev;

    node = ip6_addr;
    while (node) {
        prev = node;
        node = node->next;
        free(prev);
    }
}


