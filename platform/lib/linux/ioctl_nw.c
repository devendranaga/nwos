#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "netos_macros.h"
#include "ioctl_nw.h"

int netos_get_macaddr(const char *ifname, uint8_t *macaddr)
{
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        perror("ioctl");
        return -1;
    }

    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, NETOS_MACADDR_LEN);
    close(fd);
    return 0;
}

int netos_get_ipaddr(const char *ifname, uint32_t *ipaddr)
{
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    *ipaddr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    close(fd);
    return 0;
}
