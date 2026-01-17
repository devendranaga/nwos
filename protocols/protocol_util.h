#ifndef PROTOCOL_UTIL_H
#define PROTOCOL_UTIL_H

#include <stdlib.h>

namespace netos {

bool is_broadcast_mac(uint8_t *mac)
{
    uint8_t bmac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    return memcmp(mac, bmac, sizeof(bmac)) == 0;
}

bool is_multicast_mac(uint8_t *mac)
{
    return !!(mac[0] & 0x01);
}

bool is_zero_mac(uint8_t *mac)
{
    uint8_t zmac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    return memcmp(mac, zmac, sizeof(zmac)) == 0;
}

}

#endif

