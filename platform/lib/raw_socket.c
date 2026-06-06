#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>

#include "raw_socket.h"
#include "net_ioctl.h"

raw_socket_ctx_t *netos_raw_socket_init(const char *ifname)
{
    raw_socket_ctx_t *raw;
    netos_status_t ret;
    struct sockaddr_ll lladdr;
    int ifindex;
    int res;

    raw = calloc(1, sizeof(raw_socket_ctx_t));
    if (!raw) {
        return NULL;
    }

    raw->ifname = strdup(ifname);
    raw->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw->fd < 0) {
        goto err;
    }

    // set the promiscous mode
    ret = net_ioctl_set_promisc_fd(raw->fd, ifname);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    // bind to device
    ret = net_ioctl_bind_to_device(raw->fd, ifname);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    // get the ifindex
    ifindex = net_ioctl_get_ifindex(raw->fd, ifname);
    if (ifindex == -1) {
        goto err;
    }

    memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_ifindex = ifindex;
    lladdr.sll_protocol = htons(ETH_P_ALL);
    lladdr.sll_family = AF_PACKET;

    // bind the raw socket
    res = bind(raw->fd, (struct sockaddr *)&lladdr, sizeof(lladdr));
    if (res != 0) {
        goto err;
    }

    // get mac address
    ret = netos_ioctl_get_macaddr(raw->fd, ifname, raw->mac);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    // get the ipaddress
    ret = netos_ioctl_get_ipaddr(raw->fd, ifname, &raw->ipaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    return raw;

err:
    if (raw) {
        if (raw->fd > 0) {
            close(raw->fd);
        }
        free(raw);
    }

    return NULL;
}

int netos_raw_socket_rx(raw_socket_ctx_t *raw, uint8_t *data, uint32_t data_len)
{
    struct sockaddr_ll lladdr;
    socklen_t len = sizeof(lladdr);
    int ret;

    ret = recvfrom(raw->fd, data, data_len, 0, (struct sockaddr *)&lladdr, &len);
    if (ret < 0) {
        return -1;
    }

    return ret;
}

