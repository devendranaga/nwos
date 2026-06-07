#include <stdio.h>
#include <stdint.h>
#include "netos_status.h"
#include "hash_tables.h"

uint32_t hash_val(void *key)
{
    char *a = key;
    uint32_t f = 0;

    while (*a != 0) {
        f += *a;
        a++;
    }

    return f;
}

bool for_each_print(void *key, void *val)
{
    char *a = key;
    char *b = val;

    printf("key: %s val: %s\n", a, b);

    return true;
}

int main()
{
    const struct {
        char *key;
        char *val;
    } kv_list [] = {
        {"test1", "00:01:22:33:44:55:66:77"},
        {"test2", "00:02:22:33:44:55:66:77"},
        {"test3", "00:03:22:33:44:55:66:77"},
        {"test4", "00:04:22:33:44:55:66:77"},
        {"test5", "00:05:22:33:44:55:66:77"},
        {"test6", "00:06:22:33:44:55:66:77"},
        {"test7", "00:07:22:33:44:55:66:77"},
        {"test8", "00:08:22:33:44:55:66:77"},
        {"test9", "00:09:22:33:44:55:66:77"},
        {"test10", "00:0A:22:33:44:55:66:77"},
        {"test11", "00:0B:22:33:44:55:66:77"},
        {"test12", "00:0C:22:33:44:55:66:77"},
        {"test13", "00:1D:22:33:44:55:66:77"},
        {"test14", "00:1E:22:33:44:55:66:77"},
        {"test15", "00:13:22:33:44:55:66:77"},
    };
    uint32_t i;
    netos_hash_table_t *hash_table;

    hash_table = netos_hash_table_init(8, hash_val, NULL);
    for (i = 0; i < sizeof(kv_list) / sizeof(kv_list[0]); i ++) {
        netos_hash_item_add(hash_table, kv_list[i].key, kv_list[i].val);
    }

    netos_hash_item_for_each(hash_table, for_each_print);

    return 0;
}

