
#include <stdint.h>
#include <string>

#include "conversion.h"
#include "error_codes.h"

namespace netos {

namespace lib {

netos_status str_to_mac(const std::string &mac, uint8_t *mac_u8)
{
    int ret;
    uint32_t mac_u32[6];

    ret = sscanf(mac.c_str(),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 &mac_u32[0], &mac_u32[1], &mac_u32[2],
                 &mac_u32[3], &mac_u32[4], &mac_u32[5]);
    if (ret != 6) {
        return netos::lib::NETOS_STATUS_INVAL_MACADDR;
    }

    mac_u8[0] = mac_u32[0];
    mac_u8[1] = mac_u32[1];
    mac_u8[2] = mac_u32[2];
    mac_u8[3] = mac_u32[3];
    mac_u8[4] = mac_u32[4];
    mac_u8[5] = mac_u32[5];

    return netos::lib::NETOS_STATUS_SUCCESS;
}

netos_status ipaddr_str_to_uint(const std::string &str_hex, uint32_t *uint_val)
{
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    int ret;

    ret = sscanf(str_hex.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
    if (ret != 4) {
        return netos_status::NETOS_STATUS_INVAL_IPV4_ADDR;
    }

    *uint_val = (a << 24) | (b << 16) | (c << 8) | d;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status str_hex_to_int(const std::string &str_hex, uint32_t *int_val)
{
    char *err = NULL;

    *int_val = strtoul(str_hex.c_str(), &err, 16);
    if (err && (err[0] != '\0')) {
        return netos_status::NETOS_STATUS_INVAL_HEXA_STR;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

}
