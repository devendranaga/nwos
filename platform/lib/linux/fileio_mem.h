#ifndef PLATFORM_LIB_FILEIO_MEM_H
#define PLATFORM_LIB_FILEIO_MEM_H

#if defined(__cplusplus)
extern "C" {
#endif

struct fileio_map_info {
    int fd;
    uint32_t size;
    void *mapped_mem;
};

struct fileio_map_info *netos_map_file_write(const char *filename, uint32_t size);
void netos_map_file_sync(struct fileio_map_info *map_info, uint32_t len);
void netos_unmap_file(struct fileio_map_info *map_info);

#if defined(__cplusplus)
}
#endif

#endif
