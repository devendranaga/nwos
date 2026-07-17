#ifndef NETOS_MMAP_INTF_H
#define NETOS_MMAP_INTF_H

#include <stdint.h>

typedef struct netos_mmap_file_io {
    int     fd;
    void    *memory;
} netos_mmap_file_io_t;

void *netos_mmap_alloc(uint32_t buffer_size);
void netos_mmap_free(void *mem, uint32_t buffer_size);

netos_mmap_file_io_t *netos_mmap_open_file(const char *filename, uint32_t file_size);

netos_mmap_file_io_t *netos_mmap_open_file_read(const char *filename);

void netos_mmap_close_file(netos_mmap_file_io_t *fileio, uint32_t written_bytes);

#endif
