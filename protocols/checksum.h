#ifndef NETOS_CHECKSUM_H
#define NETOS_CHECKSUM_H

#include <stdbool.h>

/**
 * @brief - Defines checksum.
 */
typedef struct {
    uint8_t     *buffer;
    uint32_t    len;
    bool        is_v4;
    union {
        struct {
            uint32_t    src_ip;
            uint32_t    dst_ip;
        } v4;

        struct {
            uint8_t     *src_ip;
            uint8_t     *dst_ip;
        } v6;
    } u;
    uint8_t     protocol;
} netos_checksum_t;

uint16_t netos_ip_checksum(netos_checksum_t *chksum);

static inline uint16_t netos_ipv4_checksum(netos_checksum_t *chksum)
{
    return netos_ip_checksum(chksum);
}

static inline uint16_t netos_icmp_checksum(netos_checksum_t *chksum)
{
    return netos_ipv4_checksum(chksum);
}

static inline bool netos_icmp_verify_checksum(netos_checksum_t *chksum)
{
    return netos_icmp_checksum(chksum) == 0;
}

uint16_t netos_l4_checksum(netos_checksum_t *chksum);

#endif

