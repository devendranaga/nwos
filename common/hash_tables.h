#ifndef NETOS_LIB_HASH_TABLES_H
#define NETOS_LIB_HASH_TABLES_H

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t (*hash_fn)(void *key);
typedef bool     (*for_each_fn)(void *ctx, void *key, void *val);
typedef bool     (*del_fn)(void *key, void *val);
typedef bool     (*cmp_fn)(void *key1, void *key2);

typedef struct netos_hash_item {
    void *key;
    void *val;
    struct netos_hash_item *next;
} netos_hash_item_t;

typedef struct netos_hash_table {
    netos_hash_item_t   **items;
    uint32_t            n_items;
    hash_fn             hash;
    cmp_fn              cmp;
} netos_hash_table_t;

netos_hash_table_t *netos_hash_table_init(uint32_t n_items, hash_fn hash, cmp_fn cmp);

netos_status_t netos_hash_item_add(netos_hash_table_t *hash_table, void *key, void *val);

void netos_hash_item_for_each(netos_hash_table_t *hash_table, void *ctx, for_each_fn for_each);

void *netos_hash_item_find(netos_hash_table_t *hash_table, void *key);

void netos_hash_item_del(netos_hash_table_t *hash_table, void *key, del_fn del);

void netos_hash_table_deinit(netos_hash_table_t *hash_tbl, del_fn del);

#endif

