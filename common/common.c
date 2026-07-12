#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "netos_status.h"
#include "common.h"

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

    NETOS_SET_MACADDR(mac, mac_u32);

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

netos_status_t netos_get_u16_from_str(const char *u16_str, uint16_t *u16)
{
    char *err_ptr = NULL;

    *u16 = strtoul(u16_str, &err_ptr, 10);
    if (err_ptr && *err_ptr != '\0') {
        return NETOS_STATUS_COMMON_U16_STR_TO_U16_FAILED;
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

netos_status_t netos_get_ipv4addr_from_str(const char *ipv4addr_str, uint32_t *ipv4_addr)
{
    int res;

    res = inet_pton(AF_INET, ipv4addr_str, (uint8_t *)ipv4_addr);
    if (res <= 0) {
        return NETOS_STATUS_COMMON_IPADDR_STR_TO_HOST_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_get_bool_from_str(const char *str, bool *val)
{
    netos_status_t ret = NETOS_STATUS_COMMON_BOOL_STR_TO_BOOL_FAILED;

    if (!strcmp(str, "true")) {
        *val = true;
        ret = NETOS_STATUS_SUCCESS;
    } else if (!strcmp(str, "false")) {
        *val = false;
        ret = NETOS_STATUS_SUCCESS;
    }

    return ret;
}

