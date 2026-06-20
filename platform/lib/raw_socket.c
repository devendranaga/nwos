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
#include "netos_status.h"
#include "netos_log.h"

raw_socket_ctx_t *netos_raw_socket_init(const char *ifname)
{
    raw_socket_ctx_t *raw;
    netos_status_t ret;
    struct sockaddr_ll lladdr;
    int res;

    raw = calloc(1, sizeof(raw_socket_ctx_t));
    if (!raw) {
        netos_log_error("failed to allocate raw socket context\n");
        return NULL;
    }

    raw->ifname = strdup(ifname);
    raw->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw->fd < 0) {
        goto err;
    }

    // set the promiscous mode
    ret = netos_ioctl_set_promisc_fd(raw->fd, ifname);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    // bind to device
    ret = netos_ioctl_bind_to_device(raw->fd, ifname);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    // get the ifindex
    raw->ifindex = netos_ioctl_get_ifindex(raw->fd, ifname);
    if (raw->ifindex == -1) {
        goto err;
    }

    memset(&lladdr, 0, sizeof(lladdr));
    lladdr.sll_ifindex  = raw->ifindex;
    lladdr.sll_protocol = htons(ETH_P_ALL);
    lladdr.sll_family   = AF_PACKET;

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
        // do not fail if the address is not present.. continue
        ret = NETOS_STATUS_SUCCESS;
    }

    return raw;

err:
    if (raw) {
        if (raw->fd > 0) {
            close(raw->fd);
        }
        if (raw->ifname) {
            free(raw->ifname);
        }
        free(raw);
    }

    return NULL;
}

void netos_raw_socket_deinit(raw_socket_ctx_t *raw)
{
    if (raw) {
        if (raw->fd > 0) {
            netos_ioctl_clear_promisc_fd(raw->fd, raw->ifname);
            close(raw->fd);
        }
        if (raw->ifname) {
            free(raw->ifname);
        }
        free(raw);
    }
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

int netos_raw_socket_tx(raw_socket_ctx_t *raw, uint8_t *data, uint32_t data_len)
{
    struct sockaddr_ll lladdr;

    lladdr.sll_ifindex = raw->ifindex;
    lladdr.sll_halen = ETH_ALEN;
    lladdr.sll_addr[0] = 0x00;
    lladdr.sll_addr[1] = 0x00;
    lladdr.sll_addr[2] = 0x00;
    lladdr.sll_addr[3] = 0x00;
    lladdr.sll_addr[4] = 0x00;
    lladdr.sll_addr[5] = 0x00;

    return sendto(raw->fd, data, data_len, 0,
                 (struct sockaddr *)&lladdr, sizeof(struct sockaddr_ll));
}

