#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "netos_status.h"
#include "mmap_intf.h"

void *netos_mmap_alloc(uint32_t buffer_size)
{
    void *mem;

    // allocate hugetlb page
    mem = mmap(NULL, buffer_size,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_HUGETLB | MAP_ANONYMOUS,
               -1, 0);
    if (mem == MAP_FAILED) {
        // if hugetlb page allocation failed, allocate normal page
        mem = mmap(NULL, buffer_size,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS,
                   -1, 0);
        if (mem == MAP_FAILED) {
            return NULL;
        }
    }

    return mem;
}

netos_mmap_file_io_t *netos_mmap_open_file(const char *filename, uint32_t file_size)
{
    netos_mmap_file_io_t *fileio;
    int ret;

    fileio = calloc(1, sizeof(netos_mmap_file_io_t));
    if (!fileio) {
        return NULL;
    }

    fileio->fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0660);
    if (fileio->fd < 0) {
        goto err;
    }

    ret = ftruncate(fileio->fd, file_size);
    if (ret != 0) {
        goto err;
    }

    fileio->memory = mmap(NULL, file_size,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED,
                          fileio->fd, 0);
    if (fileio->memory == MAP_FAILED) {
        goto err;
    }

    return fileio;

err:
    if (fileio) {
        if (fileio->fd >= 0) {
            close(fileio->fd);
        }
        free(fileio);
    }

    return NULL;
}

netos_mmap_file_io_t *netos_mmap_open_file_read(const char *filename)
{
    netos_mmap_file_io_t *fileio;
    struct stat st;
    int ret;

    ret = stat(filename, &st);
    if (ret != 0) {
        return NULL;
    }

    fileio = calloc(1, sizeof(netos_mmap_file_io_t));
    if (!fileio) {
        return NULL;
    }

    fileio->fd = open(filename, O_RDONLY);
    if (fileio->fd < 0) {
        goto err;
    }

    ret = ftruncate(fileio->fd, st.st_size);
    if (ret != 0) {
        goto err;
    }

    fileio->memory = mmap(NULL, st.st_size,
                          PROT_READ,
                          MAP_SHARED,
                          fileio->fd, 0);
    if (fileio->memory == MAP_FAILED) {
        goto err;
    }

    return fileio;

err:
    if (fileio) {
        if (fileio->fd >= 0) {
            close(fileio->fd);
        }
        free(fileio);
    }

    return NULL;
}

void netos_mmap_close_file(netos_mmap_file_io_t *fileio, uint32_t written_bytes)
{
    if (fileio) {
        msync(fileio->memory, written_bytes, MS_SYNC);
        munmap(fileio->memory, written_bytes);
        close(fileio->fd);
        free(fileio);
    }
}

void netos_mmap_free(void *mem, uint32_t buffer_size)
{
    if (mem) {
        munmap(mem, buffer_size);
    }
}
