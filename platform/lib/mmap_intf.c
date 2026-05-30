#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

#include "netos_status.h"

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

void netos_mmap_free(void *mem, uint32_t buffer_size)
{
    if (mem) {
        munmap(mem, buffer_size);
    }
}