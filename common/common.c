#include <stdint.h>
#include <stdio.h>
#include "netos_status.h"

netos_status_t netos_get_mac_addr_from_str(const char *mac_str, uint8_t *mac)
{
    uint32_t mac_u32[6];
    int ret;

    ret = sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                          &mac_u32[0], &mac_u32[1],
                          &mac_u32[2], &mac_u32[3],
                          &mac_u32[4], &mac_u32[5]);
    if (ret != 6) {
        return NETOS_STATUS_COMMON_MAC_STR_TO_U8_FAILED;
    }

    mac[0] = mac_u32[0];
    mac[1] = mac_u32[1];
    mac[2] = mac_u32[2];
    mac[3] = mac_u32[3];
    mac[4] = mac_u32[4];
    mac[5] = mac_u32[5];

    return NETOS_STATUS_SUCCESS;
}

