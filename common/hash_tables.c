#include <stdio.h>
#include <stdlib.h>
#include "netos_status.h"
#include "hash_tables.h"

netos_hash_table_t *netos_hash_table_init(uint32_t n_items, hash_fn hash, cmp_fn cmp)
{
    netos_hash_table_t *hash_table;

    hash_table = calloc(1, sizeof(netos_hash_table_t));
    if (!hash_table) {
        return NULL;
    }

    hash_table->n_items = n_items;
    hash_table->hash = hash;
    hash_table->cmp = cmp;

    hash_table->items = calloc(1, sizeof(netos_hash_item_t) * n_items);
    if (!hash_table->items) {
        goto err;
    }

    for (uint32_t i = 0; i < n_items; i ++) {
        hash_table->items[i] = NULL;
    }

    return hash_table;

err:
    if (hash_table) {
        if (hash_table->items) {
            free(hash_table->items);
        }
        free(hash_table);
    }

    return NULL;
}

netos_status_t netos_hash_item_add(netos_hash_table_t *hash_table, void *key, void *val)
{
    netos_hash_item_t *entry;
    netos_hash_item_t *item;
    netos_hash_item_t *prev;
    uint32_t index;

    index = hash_table->hash(key) % hash_table->n_items;
    item = hash_table->items[index];

    entry = calloc(1, sizeof(netos_hash_item_t));
    if (!entry) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    entry->key = key;
    entry->val = val;

    if (!item) {
        hash_table->items[index] = entry;
        return NETOS_STATUS_SUCCESS;
    } else {
        prev = item;
        while (item) {
            prev = item;
            item = item->next;
        }

        prev->next = entry;
    }

    return NETOS_STATUS_SUCCESS;
}

void netos_hash_item_for_each(netos_hash_table_t *hash_table, for_each_fn for_each)
{
    uint32_t i;

    if (!for_each) {
        return;
    }

    for (i = 0; i < hash_table->n_items; i ++) {
        netos_hash_item_t *item;

        for (item = hash_table->items[i]; item != NULL; item = item->next) {
            for_each(item->key, item->val);
        }
    }
}

void *netos_hash_item_find(netos_hash_table_t *hash_table, void *key)
{
    netos_hash_item_t *item;
    uint32_t index;

    index = hash_table->hash(key) % hash_table->n_items;
    item = hash_table->items[index];

    if (!item) {
        return NULL;
    }

    if (hash_table->cmp(key, item->key)) {
        return item->val;
    } else {
        while (item) {
            if (hash_table->cmp(key, item->key)) {
                return item->val;
            }

            item = item->next;
        }
    }

    return NULL;
}

void netos_hash_item_del(netos_hash_table_t *hash_table, void *key, del_fn del)
{
    netos_hash_item_t *item;
    uint32_t index;

    index = hash_table->hash(key) % hash_table->n_items;
    item = hash_table->items[index];

    if (hash_table->cmp(key, item->key)) {
        hash_table->items[index] = item->next;
        if (del(item->key, item->val)) {
            free(item);
        }
    } else {
        netos_hash_item_t *entry;

        while (item) {
            entry = item;
            if (hash_table->cmp(key, item->key)) {
                entry->next = item->next;
                if (del(item->key, item->val)) {
                    free(item);
                }
            }
            item = item->next;
        }
    }
}

