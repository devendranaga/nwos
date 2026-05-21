#include <stdio.h>
#include <stdint.h>
#include "queue_impl.h"

bool lookup(uint32_t *a, uint32_t *b)
{
    return *a == *b;
}

int main()
{
    uint32_t a[] = {1, 2, 3, 4, 5, 6, 7};
    netos::lib::queue_impl<uint32_t *> q(lookup);
    uint32_t i;

    for (i = 0; i < sizeof(a)/sizeof(a[0]); i ++) {
        q.push(&a[i]);
    }

    uint32_t *ptr = nullptr;
    while (q.pop(&ptr)) {
        uint32_t *ptr1 = nullptr;
        uint32_t *tail = nullptr;

        q.front(&ptr1);
        q.back(&tail);

        printf("ptr     %d\n", *ptr);
        if (ptr1)
            printf("front   %d\n", *ptr1);
        if (tail)
            printf("back    %d\n", *tail);

    }

    return 0;
}
