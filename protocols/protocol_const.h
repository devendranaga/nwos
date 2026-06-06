#ifndef NETOS_PROTOCOL_CONST_H
#define NETOS_PROTOCOL_CONST_H

#define NETOS_MACADDR_LEN 6
#define NETOS_MACADDR_STR "%02x:%02x:%02x:%02x:%02x:%02x"
#define NETOS_MACADDR_BUF(__buf) __buf[0], __buf[1], __buf[2], __buf[3], __buf[4], __buf[5]
#define NETOS_IS_ZERO_IPADDR(__ipaddr) (__ipaddr == 0x00)
#define NETOS_IS_BROADCAST_IPADDR(__ipaddr) (__ipaddr = 0xFFFFFFFF)

#endif

