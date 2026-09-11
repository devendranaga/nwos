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

/**
 * @brief - Find the value given the key.
 *
 * @param [inout] hash_table - hash table context.
 * @param [in] key - input key for lookup.
 *
 * @return returns a valid value pointer on success and NULL on error.
 */
void *netos_hash_item_find(netos_hash_table_t *hash_table, void *key);

/**
 * @brief - Delete a hash table entry after a key lookup.
 *
 * Calls delete function if valid.
 *
 * @param [inout] hash_table - hash table context.
 * @param [in] del - delete callback.
 */
void netos_hash_item_del(netos_hash_table_t *hash_table, void *key, del_fn del);

/**
 * @brief - Deinit the hash tables and call del callback to free up keys and values.
 *
 * hash_tbl must be a valid pointer.
 *
 * if delete callback is not set, function will not free anything.
 *
 * @param [inout] hash_tbl - hash table context.
 * @param [in] del - delete callback.
 */
void netos_hash_table_deinit(netos_hash_table_t *hash_tbl, del_fn del);

#endif

