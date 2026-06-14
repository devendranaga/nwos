#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

netos_status_t netos_get_u16_hex_from_str(const char *hex_str, uint16_t *hex)
{
    char *err_ptr = NULL;

    *hex = strtoul(hex_str, &err_ptr, 16);
    if (err_ptr && *err_ptr != '\0') {
        return NETOS_STATUS_COMMON_U16_STR_TO_U16_HEX_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_get_u32_from_str(const char *u32_str, uint32_t *u32)
{
    char *err_ptr = NULL;

    *u32 = strtoul(u32_str, &err_ptr, 10);
    if (err_ptr && *err_ptr != '\0') {
        return NETOS_STATUS_COMMON_U32_STR_TO_U32_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_get_u64_from_str(const char *u64_str, uint64_t *u64)
{
    char *err_ptr = NULL;

    *u64 = strtoul(u64_str, &err_ptr, 10);
    if (err_ptr && *err_ptr != '\0') {
        return NETOS_STATUS_COMMON_U64_STR_TO_U64_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

