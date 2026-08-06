#ifndef NETOS_COMMON_H
#define NETOS_COMMON_H

#include <string.h>

#define NETOS_SIZEOF_ARRAY(__a) ((sizeof(__a)) / (sizeof(__a[0])))

static inline bool netos_is_broadcast_mac(const uint8_t *mac)
{
    const uint8_t bmac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    return memcmp(mac, bmac, sizeof(bmac)) == 0;
}

/**
 * @brief - Get Mac address from the input string.
 *
 * @param [in] mac_str - Mac Address string.
 * @param [out] mac - u8 mac address.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_get_mac_addr_from_str(const char *mac_str, uint8_t *mac);

/**
 * @brief - Get u16 hex from the input string.
 *
 * @param [in] hex_str - hexadecimal string.
 * @param [out] hex - output u16 hexadecimal.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_get_u16_hex_from_str(const char *hex_str, uint16_t *hex);

/**
 * @brief - Get u16 from the input string.
 *
 * @param [in] string - integer string.
 * @param [out] u16 - output u16.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_get_u16_from_str(const char *u16_str, uint16_t *u16);

/**
 * @brief - Get u32 from the string.
 *
 * @param [in] u32_str - u32 in string format.
 * @param [out] u32 - output u32.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_get_u32_from_str(const char *u32_str, uint32_t *u32);

/**
 * @brief - Get u64 from the string.
 *
 * @param [in] u64_str - u64 in string format.
 * @param [out] u64 - output u64.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_get_u64_from_str(const char *u64_str, uint64_t *u64);

/**
 * @brief - Get IPv4 address from the string.
 *
 * @param [in] ipv4addr_str - IPv4 address in string format.
 * @param [out] ipv4_addr - IPv4 address.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_get_ipv4addr_from_str(const char *ipv4addr_str, uint32_t *ipv4_addr);

/**
 * @brief - Get bool from the string.
 *
 * @param [in] str - string.
 * @param [out] val - boolean value.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_get_bool_from_str(const char *str, bool *val);

/**
 * @brief - get the delta timestamp.
 *
 * @param [in] __start - start time.
 * @param [in] __end - end time.
 * @param [out] __delta - delta timestamp in nanoseconds.
 */
#define NETOS_TIMESPEC_DELTA_NS(__start, __end, __delta) do {\
    __delta = (((__end.tv_sec - __start.tv_sec) * 1000000000L) +\
               (__end.tv_nsec - __start.tv_nsec));\
} while (0)

/**
 * @brief - Get the timespec delta in seconds.
 *
 * @param [in] __start - start time.
 * @param [in] __end - end time.
 * @param [in] __delta - delta time in seconds.
 */
#define NETOS_TIMESPEC_DELTA(__start, __end, __delta) do {\
    NETOS_TIMESPEC_DELTA_NS(__start, __end, __delta);\
    __delta /= 1000000000L;\
} while (0)

/**
 * @brief - set the Mac address.
 *
 * @param [out] __tgt_mac - target mac address.
 * @param [in] __src_mac - source mac address.
 */
#define NETOS_SET_MACADDR(__tgt_mac, __src_mac) do {\
    __tgt_mac[0] = __src_mac[0];\
    __tgt_mac[1] = __src_mac[1];\
    __tgt_mac[2] = __src_mac[2];\
    __tgt_mac[3] = __src_mac[3];\
    __tgt_mac[4] = __src_mac[4];\
    __tgt_mac[5] = __src_mac[5];\
} while (0)

#endif

