#ifndef NETOS_LIST_H
#define NETOS_LIST_H

#include <stdlib.h>
#include <unistd.h>

/**
 * Circular doubly linked lists.
 */
typedef struct netos_dll {
    void *data;
    struct netos_dll *prev;
    struct netos_dll *next;
} netos_dll_t;

typedef struct netos_dll_impl {
    netos_dll_t *head;
    netos_dll_t *last;
} netos_dll_impl_t;

netos_dll_impl_t *netos_dll_init();

int netos_dll_add_item(netos_dll_impl_t *impl, void *item);

void netos_dll_for_each(netos_dll_impl_t *impl, void (*for_each_cb)(void *item));

#endif
