#ifndef NETOS_RING_H
#define NETOS_RING_H

typedef struct {
    void **items;
    uint32_t wr_index;
    uint32_t rd_index;
    uint32_t size;
} netos_ring_t;

#define NETOS_RING_EMPTY(__ring) ((__ring).rd_index == (__ring).wr_index)

netos_status_t netos_ring_init(netos_ring_t *ring, uint32_t size);

netos_status_t netos_ring_add(netos_ring_t *ring, void *item);

void *netos_ring_remove(netos_ring_t *ring);

void netos_ring_deinit(netos_ring_t *ring);

#endif

