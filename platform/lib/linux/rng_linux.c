#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "rng_linux.h"

#define NETOS_RNG_FILE_PATH "/dev/urandom"

int netos_rng_init()
{
    int fd;

    fd = open(NETOS_RNG_FILE_PATH, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    return fd;
}

int netos_rng_get_bytes(int fd, uint8_t *bytes, uint32_t len)
{
    return read(fd, bytes, len);
}

void netos_rng_exit(int fd)
{
    if (fd > 0)
        close(fd);
}


