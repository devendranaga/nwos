#include <stdint.h>
#include <stdio.h>

uint32_t netos_hash_fnv1a(uint8_t *buf, uint32_t len)
{
    uint32_t hash = 2166136261u;
    uint32_t i;

    for (i = 0; i < len; i ++) {
        hash ^= buf[i];
        hash *= 16777619u;
    }

    return hash;
}

