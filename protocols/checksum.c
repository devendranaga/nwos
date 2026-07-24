#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "checksum.h"
#include "protocol_const.h"
#include "netos_log.h"

uint16_t netos_ip_checksum(netos_checksum_t *chksum)
{
    uint32_t checksum = 0;
    uint32_t i;

    for (i = 0; i < chksum->len; i += 2) {
        checksum += (chksum->buffer[i] << 8) + (chksum->buffer[i + 1]);
    }

    if (chksum->len % 2 != 0) {
        checksum += (chksum->buffer[i] << 8);
    }

    while (checksum >> 16) {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    return ~checksum;
}

uint16_t netos_l4_checksum(netos_checksum_t *chksum)
{
    uint32_t checksum32 = 0;
    uint32_t i = 0;
    uint32_t pad = 0;

    if (chksum->len % 2) {
        pad = 1;
    }

    if (chksum->is_v4) {
        uint32_t src_ipaddr = (chksum->u.v4.src_ip);
        uint32_t dst_ipaddr = (chksum->u.v4.dst_ip);
        checksum32 = ((src_ipaddr & 0xFFFF0000) >> 16) +
                     (src_ipaddr & 0x0000FFFF);
        checksum32 += ((dst_ipaddr & 0xFFFF0000) >> 16) +
                      (dst_ipaddr & 0x0000FFFF);
    } else {
        uint8_t *src_ipaddr = chksum->u.v6.src_ip;
        uint8_t *dst_ipaddr = chksum->u.v6.dst_ip;
        for (i = 0; i < NETOS_IPV6_ADDR_LEN; i += 2) {
            checksum32 += (src_ipaddr[i] << 8) | src_ipaddr[i + 1];
        }
        for (i = 0; i < NETOS_IPV6_ADDR_LEN; i += 2) {
            checksum32 += (dst_ipaddr[i] << 8) | dst_ipaddr[i + 1];
        }
    }

    checksum32 += ((chksum->len & 0xFFFF0000) >> 16) + (chksum->len & 0x0000FFFF);
    checksum32 += chksum->protocol;

    // assuming that the checksum calculated is always until the rx buffer which is
    // 1500+ but never be as big as the allocated buffer size which is 4096.
    for (i = 0; i <= chksum->len + pad; i += 2) {
        if (i < chksum->len - 1) {
            checksum32 += (chksum->buffer[i] << 8) | (chksum->buffer[i + 1]);
        } else {
            checksum32 += chksum->buffer[i] << 8;
        }
    }

    if (checksum32 > 0xFFFF) {
        checksum32 = ((checksum32 & 0xFFFF0000) >> 16) + (checksum32 & 0x0000FFFF);
    }

    return ~checksum32;
}


