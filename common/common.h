#ifndef NETOS_COMMON_H
#define NETOS_COMMON_H

netos_status_t netos_get_mac_addr_from_str(const char *mac_str, uint8_t *mac);

netos_status_t netos_get_u16_hex_from_str(const char *hex_str, uint16_t *hex);

netos_status_t netos_get_u32_from_str(const char *u32_str, uint32_t *u32);

netos_status_t netos_get_u64_from_str(const char *u64_str, uint64_t *u64);

#endif

