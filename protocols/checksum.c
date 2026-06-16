#include <stdint.h>
#include <stdio.h>
#include "checksum.h"

uint16_t netos_ipv4_checksum(netos_checksum_t *chksum)
{
    uint32_t checksum = 0;
    uint32_t i;

    for (i = 0; i < chksum->len; i += 2) {
        checksum += (chksum->buffer[i] << 8) + (chksum->buffer[i + 1]);
    }

    if (chksum->len % 2 != 0) {
        checksum += (chksum->buffer[i] << 8);
    }

    uint32_t hi = (checksum & 0xFFFF0000) >> 16;
    uint32_t lo = (checksum & 0x0000FFFF);

    checksum = hi + lo;

    return ~checksum;
}


