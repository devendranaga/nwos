#include <stdint.h>

#include "queue.h"

netos_queue_impl_t *netos_queue_init()
{
    netos_queue_impl_t *impl;

    impl = calloc(1, sizeof(netos_queue_impl_t));
    if (!impl) {
        return NULL;
    }

    impl->head = NULL;
    impl->tail = NULL;
    impl->length = 0;

    return impl;
}

void netos_queue_push(netos_queue_impl_t *impl, void *item)
{
    netos_queue_t *node;

    node = calloc(1, sizeof(netos_queue_impl_t));
    if (!node) {
        return;
    }

    node->item = item;
    node->next = NULL;

    if (!impl->head) {
        impl->head = node;
        impl->tail = node;
    } else {
        impl->tail->next = node;
        impl->tail = node;
    }

    impl->length ++;
}

void *netos_queue_pop(netos_queue_impl_t *impl)
{
    netos_queue_t *node;
    void *item;

    node = impl->head;
    if (!node) {
        return NULL;
    }

    item = node->item;
    impl->head = impl->head->next;
    free(node);

    impl->length --;

    return item;
}
