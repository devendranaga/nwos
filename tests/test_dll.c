#include <stdint.h>
#include <stdio.h>
#include <list.h>

void for_each_cb(void *item)
{
    printf("item %d\n", *(uint32_t *)item);
}

int main()
{
    uint32_t items[] = {1, 2, 3, 4, 5, 6, 7};
    netos_dll_impl_t *impl;

    impl = netos_dll_init();
    if (!impl) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < sizeof(items) / sizeof(items[0]); i ++) {
        netos_dll_add_item(impl, &items[i]);
    }

    netos_dll_for_each(impl, for_each_cb);

    return 0;
}