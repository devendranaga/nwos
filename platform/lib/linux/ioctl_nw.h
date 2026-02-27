#ifndef NETOS_IOCTL_NW_H
#define NETOS_IOCTL_NW_H

#if defined(__cplusplus)
extern "C" {
#endif

int netos_get_macaddr(const char *ifname, uint8_t *macaddr);

int netos_get_ipaddr(const char *ifname, uint32_t *ipaddr);

#if defined(__cplusplus)
}
#endif

#endif
