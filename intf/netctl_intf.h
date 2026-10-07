#ifndef NETOS_NETCTL_INTF_H
#define NETOS_NETCTL_INTF_H

#define NETOS_NETCTL_VERSION                1

#define NETOS_NETCTL_GET_INTERFACES         1
#define NETOS_NETCTL_GET_INGRESS_STATS      2
#define NETOS_NETCTL_GET_EGRESS_STATS       3
#define NETOS_NETCTL_STATUS                 0xa0a0a0a0

#define NETOS_NETCTL_INVAL_VERSION          1
#define NETOS_NETCTL_UNKNOWN_TYPE           2

typedef struct __attribute__ ((__packed__)) {
    uint32_t status_code;
} netos_netctl_status_t;

typedef struct __attribute__ ((__packed__)) {
    uint32_t    version;
    uint32_t    type;
    uint8_t     val[0];
} netos_netctl_intf_t;

#define NETOS_NETCTL_INTF_INIT(__intf, __type) do {\
    __intf->version = NETOS_NETCTL_VERSION;\
    __intf->type = __type;\
} while (0)

#endif

