#ifndef LIB_ALGORITHMS_HASH_H
#define LIB_ALGORITHMS_HASH_H

#if defined(__cplusplus)
extern "C" {
#endif

// Defines a hash item in the hash bucket
//
// item is the value to be stored and the key is where
// the searching can be used to perform the match.
struct netos_hash_item {
    void *item;
    void *key;
    struct netos_hash_item *next;
};

// Defines a hash table with a set of buckets
//
// Each bucket then is a linked list.
struct netos_hash_table {
    struct netos_hash_item **buckets;
    uint32_t size;
};

// Initialize the hash table.
//
// @param [in] size - hash table buckets
//
// @return returns the hash table pointer
struct netos_hash_table* netos_hash_table_init(uint32_t size);

// Add an item in the hash table.
//
// @param [in] ctx - hash table pointer.
// @param [in] item - any type of user data.
// @param [in] key - key to set in the hash list
// @param [in] callback_hash - a pointer to a callback function that returns the hash
//
// Generally we define a custom hash function so that the user can specify what type of
// hash they want to use so that the hashing logic can be per application specific and
// will not be generalized for all the usecases.
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
