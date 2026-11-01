#ifndef NETOS_NET_IOCTL_H
#define NETOS_NET_IOCTL_H

#include "protocol_const.h"

typedef struct netos_raw_ip6addr {
    uint8_t ip6addr[NETOS_IPV6_ADDR_LEN];
    struct netos_raw_ip6addr *next;
} netos_ctl_ip6addr_t;

/**
 * @brief - Set an interface (Raw sockfd) in the promiscous mode.
 *
 * @param [in] fd - file descriptor
 * @param [in] ifname - interface name
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_ioctl_set_promisc_fd(int fd, const char *ifname);

/**
 * @brief - Clear an interface (Raw sockfd) from the promiscous mode.
 *
 * @param [in] fd - file descriptor
 * @param [in] ifname - interface name
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_ioctl_clear_promisc_fd(int fd, const char *ifname);

/**
 * @brief - Bind the fd to the interface.
 *
 * @param [in] fd - file descriptor
 * @param [in] ifname - interface name
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_ioctl_bind_to_device(int fd, const char *ifname);

int netos_ioctl_get_ifindex(int fd, const char *ifname);

netos_status_t netos_ioctl_get_macaddr(int fd, const char *ifname, uint8_t *macaddr);

netos_status_t netos_ioctl_get_ipaddr(int fd, const char *ifname, uint32_t *ipaddr);

netos_status_t netos_ioctl_get_mtu(int fd, const char *ifname, uint32_t *mtu);

netos_ctl_ip6addr_t *netos_ioctl_get_ip6addrs(void);

void netos_ioctl_free_ip6addrs(netos_ctl_ip6addr_t *ip6_addr);

#endif

