#ifndef NETOS_MMAP_INTF_H
#define NETOS_MMAP_INTF_H

#include <stdint.h>

void *netos_mmap_alloc(uint32_t buffer_size);
void netos_mmap_free(void *mem, uint32_t buffer_size);

#endif
