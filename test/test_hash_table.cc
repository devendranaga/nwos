#include <iostream>
#include "hash_table.h"

static netos::lib::hash_table<uint32_t, uint32_t> ht;

uint32_t hash_fn(uint32_t key)
{
    return key;
}

bool find_fn(uint32_t key_i, uint32_t key_ii)
{
    return key_i == key_ii;
}

void del_fn(uint32_t key_i, uint32_t val_i)
{

}

bool for_each_fn(uint32_t key_i, uint32_t val_i)
{
    printf("for each key: %d val: %d\n", key_i, val_i);

    if (key_i == 10) {
        printf("delete %d\n", key_i);
        ht.remove(key_i);
        return true;
    }

    return false;
}

int main()
{
    struct {
        uint32_t key;
        uint32_t val;
    } kv_list[ ] = {
        {1, 10},
        {2, 20},
        {3, 30},
        {4, 40},
        {5, 50},
        {6, 60},
        {7, 70},
        {8, 80},
        {9, 90},
        {10, 100},
        {11, 110},
        {12, 120},
        {13, 130},
        {14, 140},
        {15, 150},
        {16, 160},
        {17, 170},
        {18, 180},
        {19, 190},
        {20, 200}
    };
    int ret;

    ret = ht.initialize(4, hash_fn, find_fn, del_fn, for_each_fn);
    if (ret != 0) {
        printf("failed to initialize hash table\n");
        return -1;
    }

    for (uint32_t i = 0; i < sizeof(kv_list) / sizeof(kv_list[0]); i ++) {
        ht.add(kv_list[i].key, kv_list[i].val);
    }

    ht.for_each();
}