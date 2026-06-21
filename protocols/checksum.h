#ifndef NETOS_CHECKSUM_H
#define NETOS_CHECKSUM_H

#include <stdbool.h>

/**
 * @brief - Defines checksum.
 */
typedef struct {
    uint8_t     *buffer;
    uint32_t    len;
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

#endif

