#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netos_status.h"
#include "ring.h"
#include "netos_log.h"

netos_status_t netos_ring_init(netos_ring_t *ring, uint32_t size)
{
    ring->items = calloc(1, sizeof(void *) * size);
    if (!ring->items) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    ring->wr_index = 0;
    ring->rd_index = 0;
    ring->size = size;

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ring_add(netos_ring_t *ring, void *item)
{
    if (((ring->wr_index + 1) % ring->size) == ring->rd_index) {
        netos_log_info("failed to add to the ring");
        return NETOS_STATUS_RING_BUFFER_FULL;
    }

    ring->items[ring->wr_index] = item;
    ring->wr_index = (ring->wr_index + 1) % ring->size;

    return NETOS_STATUS_SUCCESS;
}

void *netos_ring_remove(netos_ring_t *ring)
{
    if (ring->rd_index == ring->wr_index) {
        return NULL;
    }

    void *val = ring->items[ring->rd_index];
    ring->rd_index = (ring->rd_index + 1) % ring->size;

    return val;
}

void netos_ring_deinit(netos_ring_t *ring)
{
    if (ring->items) {
        free(ring->items);
    }

    ring->wr_index = 0;
    ring->rd_index = 0;
    ring->size = 0;
}

