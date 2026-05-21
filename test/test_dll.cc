#include <stdio.h>
#include <stdint.h>

#include "doubly_linked_list.h"

void del_fn(uint32_t *data)
{

}

void for_each_fwd(uint32_t *data)
{
    printf("FWD: %d\n", *data);
}

void for_each_rvrs(uint32_t *data)
{
    printf("RVRS: %d\n", *data);
}

bool compare_fn(uint32_t *data1, uint32_t *data2)
{
    return *data1 == *data2;
}

int main()
{
    uint32_t a[] = {1, 2, 3, 4, 5, 6, 7};
    netos::lib::doubly_linked_list<uint32_t *> dll;

    dll.initialize(del_fn, compare_fn, for_each_fwd, for_each_rvrs);
    for (uint32_t i = 0; i < sizeof(a) / sizeof(a[0]); i ++) {
        dll.add(&a[i]);
    }

    dll.for_each_fwd();
    dll.del(&a[0]);
    dll.del(&a[4]);
    dll.del(&a[6]);
    dll.for_each_rvrs();

    dll.deinitialize();

    return 0;
}
