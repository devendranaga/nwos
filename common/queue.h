#ifndef NETOS_QUEUE_H
#define NETOS_QUEUE_H

#include <stdlib.h>

typedef struct netos_queue {
    void *item;
    struct netos_queue *next;
} netos_queue_t;

typedef struct netos_queue_impl {
    netos_queue_t *head;
    netos_queue_t *tail;
    uint32_t length;
} netos_queue_impl_t;

netos_queue_impl_t *netos_queue_init();

void netos_queue_push(netos_queue_impl_t *impl, void *item);

void *netos_queue_pop(netos_queue_impl_t *impl);

#endif
