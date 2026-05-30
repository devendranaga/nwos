#include <stdio.h>
#include <stdint.h>
#include "queue.h"

int main()
{
    uint32_t items[] = {1, 2, 3, 4, 5, 6, 7};
    netos_queue_impl_t *q;

    q = netos_queue_init();
    if (!q) {
        return -1;
    }

    for (uint32_t i = 0; i < sizeof(items) / sizeof(items[0]); i ++) {
        netos_queue_push(q, &items[i]);
    }

    while (1) {
        uint32_t *item = netos_queue_pop(q);

        if (!item) {
            break;
        }
        printf("item %d\n", *item);
    }

    return 0;
}