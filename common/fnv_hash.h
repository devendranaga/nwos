#ifndef NETOS_FNV_HASH_H
#define NETOS_FNV_HASH_H

#include <stdint.h>

uint32_t netos_hash_fnv1a(uint8_t *buf, uint32_t len);

#endif

