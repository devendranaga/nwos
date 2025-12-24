
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

}

}
