#ifndef NETOS_PLATFORM_LIB_LINUX_RNG_LINUX_H
#define NETOS_PLATFORM_LIB_LINUX_RNG_LINUX_H

#if defined(__cplusplus)
extern "C" {
#endif

int netos_rng_init();
int netos_rng_get_bytes(int fd, uint8_t *bytes, uint32_t len);
void netos_rng_exit(int fd);

#if defined(__cplusplus)
}
#endif

#endif

