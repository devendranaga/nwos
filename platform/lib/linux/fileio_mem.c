#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "fileio_mem.h"

struct fileio_map_info *netos_map_file_write(const char *filename, uint32_t size)
{
    struct fileio_map_info *map_info;

    map_info = (struct fileio_map_info *)calloc(1, sizeof(*map_info));
    if (!map_info) {
        return NULL;
    }

    map_info->fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (map_info->fd == -1) {
        goto free_map_info;
    }
    map_info->size = size;

    if (ftruncate(map_info->fd, size) == -1) {
        goto free_map_info;
    }

    map_info->mapped_mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, map_info->fd, 0);
    if (map_info->mapped_mem == MAP_FAILED) {
        goto free_map_info;
    }

    return map_info;

free_map_info:
    if (map_info) {
        if (map_info->fd > 0) {
            close(map_info->fd);
        }
        free(map_info);
    }

    return NULL;
}

void netos_map_file_sync(struct fileio_map_info *map_info, uint32_t len)
{
    if (map_info && (map_info->fd > 0) && map_info->mapped_mem) {
        msync(map_info->mapped_mem, len, MS_SYNC);
        ftruncate(map_info->fd, len);
    }
}

void netos_unmap_file(struct fileio_map_info *map_info)
{
    if (map_info) {
        if (map_info->mapped_mem) {
            munmap(map_info->mapped_mem, map_info->size);
        }
        if (map_info->fd > 0) {
            close(map_info->fd);
        }
        free(map_info);
    }
}

