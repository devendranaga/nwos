#include <stdio.h>
#include <stdbool.h>

#include "list.h"

netos_dll_impl_t *netos_dll_init()
{
    netos_dll_impl_t *impl = calloc(1, sizeof(netos_dll_impl_t));

    if (!impl)
        return NULL;

    impl->head = NULL;
    impl->last = NULL;

    return impl;
}

int netos_dll_add_item(netos_dll_impl_t *impl, void *item)
{
    netos_dll_t *new_node = calloc(1, sizeof(netos_dll_t));

    if (!new_node)
        return -1;

    new_node->data = item;
    new_node->prev = new_node;
    new_node->next = new_node;

    if (!impl->head) {
        impl->head = new_node;
        impl->last = new_node;
        impl->last->next = new_node;
    } else {
        new_node->next = impl->head;
        new_node->prev = impl->head->prev;
        impl->head = new_node;
        impl->head->prev = impl->last;
        impl->last->next = impl->head;
    }

    return 0;
}

void netos_dll_for_each(netos_dll_impl_t *impl, void (*for_each_cb)(void *item))
{
    netos_dll_t *dll = impl->head;

    if (!dll) {
        return;
    }

    do {
        if (for_each_cb) {
            for_each_cb(dll->data);
        }

        dll = dll->next;
    } while (dll != impl->head);
}

bool netos_dll_delete_item(netos_dll_impl_t *impl, void *item)
{
    netos_dll_t *node;

    if (!impl->head) {
        return false;
    }

    if (impl->head->data == item) {
        if (impl->last == impl->head) {
            free(impl->head);
            impl->head = NULL;
            impl->last = NULL;
        } else {
            netos_dll_t *head = impl->head;

            impl->head = impl->head->next;
            impl->head->prev = impl->last;
            impl->last->next = impl->head;
            free(head);
        }
        return true;
    }

    node = impl->head->next;
    while (node != impl->head) {
        if (node->data == item) {
            node->prev->next = node->next;
            node->next->prev = node->prev;

            if (node == impl->last) {
                impl->last = node->prev;
            }
            free(node);
            return true;
        }
        node = node->next;
    }

    return false;
}

