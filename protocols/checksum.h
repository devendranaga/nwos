#ifndef NETOS_CHECKSUM_H
#define NETOS_CHECKSUM_H

typedef struct {
    uint8_t *buffer;
    uint32_t len;
} netos_checksum_t;

uint16_t netos_ipv4_checksum(netos_checksum_t *chksum);

#endif

