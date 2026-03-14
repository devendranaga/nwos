#ifndef NETOS_PLATFORM_HELPERS_IP_COMPARE_H
#define NETOS_PLATFORM_HELPERS_IP_COMPARE_H

#include <stdint.h>

inline bool netos_ipv6_compare(const uint8_t *src_addr, const uint8_t *dst_addr)
{
    const uint64_t *src_addr8 = (const uint64_t *)src_addr;
    const uint64_t *dst_addr8 = (const uint64_t *)dst_addr;

    return ((src_addr8[0] == dst_addr8[0]) &&
            (src_addr8[1] == dst_addr8[1]));
}

#endif

