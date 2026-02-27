#ifndef PLATFORM_LIB_QUEUE_H
#define PLATFORM_LIB_QUEUE_H

#include <stdint.h>
#include <pthread.h>

struct netos_queue {
    uint32_t available;
    void *data;
};

struct netos_queue_context {
    struct netos_queue *items;
    uint32_t n_items;
    uint32_t head;
    uint32_t tail;
    pthread_mutex_t lock;
};

struct netos_queue_context *netos_queue_init(uint32_t n_items);

int netos_queue_add_item(struct netos_queue_context *context, void *item);

void *netos_queue_get_item(struct netos_queue_context *context);

void netos_queue_deinit(struct netos_queue_context *context,
                        void (*callback)(void *item));

#endif

