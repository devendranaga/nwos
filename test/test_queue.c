#include <stdio.h>
#include "queue.h"

int main()
{
    struct netos_queue_context *context;
    uint32_t a[100];
    uint32_t i;

    for (i = 0; i < 100; i ++) {
        a[i] = i;
    }

    context = netos_queue_init(100);
    for (i = 0; i < 100; i ++) {
        netos_queue_add_item(context, &a[i]);
    }

    void *item;
    while ((item = netos_queue_get_item(context)) != NULL) {
        printf("val %d\n", *(uint32_t *)item);
    }

    netos_queue_deinit(context, NULL);

    return 0;
}

