#include <stdio.h>
#include <stdint.h>
#include <net/if.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "netos_status.h"
#include "protocol_const.h"

netos_status_t net_ioctl_set_promisc_fd(int fd, const char *ifname)
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

netos_status_t net_ioctl_bind_to_device(int fd, const char *ifname)
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

int net_ioctl_get_ifindex(int fd, const char *ifname)
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
    *ipaddr = ifaddr->sin_addr.s_addr;

    return NETOS_STATUS_SUCCESS;
}

