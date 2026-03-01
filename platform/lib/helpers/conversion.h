#ifndef NETOS_PLATFORM_LIB_HELPERS_CONVERSION_H
#define NETOS_PLATFORM_LIB_HELPERS_CONVERSION_H

#include <stdint.h>
#include <string>

#include "error_codes.h"

namespace netos {

namespace lib {

/**
 * @brief - convert mac string to mac address.
 *
 * @param [in] mac - mac string.
 * @param [out] mac_u8 - mac bytes.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status str_to_mac(const std::string &mac, uint8_t *mac_u8);
netos_status ipaddr_str_to_uint(const std::string &str_hex, uint32_t *uint_val);
netos_status str_hex_to_int(const std::string &str_hex, uint32_t *int_val);

}

}

#endif
