#include <stdlib.h>

#include "queue.h"

struct netos_queue_context *netos_queue_init(uint32_t n_items)
{
    struct netos_queue_context *context;
    uint32_t i;

    context = (struct netos_queue_context *)calloc(1, sizeof(struct netos_queue_context));
    if (!context) {
        return NULL;
    }

    context->items = calloc(1, sizeof(struct netos_queue) * n_items);
    if (!context->items) {
        free(context);
        return NULL;
    }

    for (i = 0; i < n_items; i ++) {
        context->items[i].available = 1;
    }

    context->n_items = n_items;
    context->head = 0;
    context->tail = 0;

    pthread_mutex_init(&context->lock, NULL);

    return context;
}

int netos_queue_add_item(struct netos_queue_context *context, void *item)
{
    uint32_t index;

    pthread_mutex_lock(&context->lock);

    index = context->tail % context->n_items;

    context->items[index].data = item;
    context->items[index].available = 0;
    context->tail = index + 1;

    pthread_mutex_unlock(&context->lock);

    return 0;
}

void *netos_queue_get_item(struct netos_queue_context *context)
{
    void *item = NULL;
    uint32_t index;

    pthread_mutex_lock(&context->lock);

    index = context->head % context->n_items;

    if (context->items[index].available == 0) {
        item = context->items[index].data;
        context->items[index].available = 1;
        context->head = index + 1;
    }

    pthread_mutex_unlock(&context->lock);

    return item;
}

void netos_queue_deinit(struct netos_queue_context *context,
                        void (*callback)(void *item))
{
    uint32_t i;

    if (context && context->items) {
        for (i = 0; i < context->n_items; i ++) {
            if (callback) {
                callback(context->items[i].data);
            }
        }
        free(context->items);
        free(context);
    }
}


