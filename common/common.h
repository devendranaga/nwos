#ifndef NETOS_COMMON_H
#define NETOS_COMMON_H

netos_status_t netos_get_mac_addr_from_str(const char *mac_str, uint8_t *mac);

netos_status_t netos_get_u16_hex_from_str(const char *hex_str, uint16_t *hex);

netos_status_t netos_get_u32_from_str(const char *u32_str, uint32_t *u32);

netos_status_t netos_get_u64_from_str(const char *u64_str, uint64_t *u64);

netos_status_t netos_get_ipv4addr_from_str(const char *ipv4addr_str, uint32_t *ipv4_addr);

#define NETOS_TIMESPEC_DELTA_NS(__start, __end, __delta) do {\
    __delta = (((__end.tv_sec - __start.tv_sec) * 1000000000L) +\
               (__end.tv_nsec - __start.tv_nsec));\
} while (0)

#define NETOS_TIMESPEC_DELTA(__start, __end, __delta) do {\
    NETOS_TIMESPEC_DELTA_NS(__start, __end, __delta);\
    __delta /= 1000000000L;\
} while (0)

#define NETOS_SET_MACADDR(__tgt_mac, __src_mac) do {\
    __tgt_mac[0] = __src_mac[0];\
    __tgt_mac[1] = __src_mac[1];\
    __tgt_mac[2] = __src_mac[2];\
    __tgt_mac[3] = __src_mac[3];\
    __tgt_mac[4] = __src_mac[4];\
    __tgt_mac[5] = __src_mac[5];\
} while (0)

#endif

