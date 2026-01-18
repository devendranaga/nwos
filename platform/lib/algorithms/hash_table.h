#ifndef LIB_ALGORITHMS_HASH_H
#define LIB_ALGORITHMS_HASH_H

#if defined(__cplusplus)
extern "C" {
#endif

struct netos_hash_item {
    void *item;
    void *key;
    struct netos_hash_item *next;
};

struct netos_hash_table {
    struct netos_hash_item **buckets;
    uint32_t size;
};

struct netos_hash_table* netos_hash_table_init(uint32_t size);
void netos_hash_table_add_item(struct netos_hash_table *ctx,
                               void *item,
                               void *key,
                               uint32_t (*callback_hash)(void *key));
void netos_hash_table_free(struct netos_hash_table *ctx, void (*callback_free)(void *ptr));
void *netos_hash_table_search(struct netos_hash_table *ctx,
                                void *key,
                                bool (*callback_compare)(void *key1, void *key2),
                                uint32_t (*callback_hash)(void *key));
void netos_hash_table_for_each(struct netos_hash_table *ctx,
                                void (*callback_func)(uint32_t bucket_number,
                                                      void *item));

#if defined(__cplusplus)
}
#endif

#endif
