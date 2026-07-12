#ifndef NETOS_LIST_H
#define NETOS_LIST_H

#include <stdlib.h>
#include <unistd.h>

/**
 * @brief - Circular doubly linked lists.
 */
typedef struct netos_dll {
    void *data;
    struct netos_dll *prev;
    struct netos_dll *next;
} netos_dll_t;

/**
 * @brief - Implements the doubly linked lists.
 */
typedef struct netos_dll_impl {
    netos_dll_t *head;
    netos_dll_t *last;
} netos_dll_impl_t;

/**
 * @brief - Initialize the doubly linked lists.
 *
 * @return returns valid pointer if success and NULL otherwise.
 */
netos_dll_impl_t *netos_dll_init();

/**
 * @brief - Add an item to the doubly linked lists.
 *
 * @param [in] impl - DLL context.
 * @param [in] item - pointer to add.
 *
 * @return 0 on success -1 on failure.
 */
int netos_dll_add_item(netos_dll_impl_t *impl, void *item);

/**
 * @brief - Iterate the DLL.
 *
 * @param [in] impl - DLL context.
 * @param [in] for_each_cb - defines a for_each_cb.
 */
void netos_dll_for_each(netos_dll_impl_t *impl,
                        void (*for_each_cb)(void *item));

#endif

