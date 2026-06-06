#ifndef NETOS_NET_IOCTL_H
#define NETOS_NET_IOCTL_H

netos_status_t net_ioctl_set_promisc_fd(int fd, const char *ifname);

netos_status_t net_ioctl_bind_to_device(int fd, const char *ifname);

int net_ioctl_get_ifindex(int fd, const char *ifname);

netos_status_t netos_ioctl_get_macaddr(int fd, const char *ifname, uint8_t *macaddr);

netos_status_t netos_ioctl_get_ipaddr(int fd, const char *ifname, uint32_t *ipaddr);

#endif

