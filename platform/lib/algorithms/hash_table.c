#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "hash_table.h"

struct netos_hash_table* netos_hash_table_init(uint32_t size)
{
    struct netos_hash_table *ht;
    
    ht = calloc(1, sizeof(struct netos_hash_table));
    if (ht == NULL) {
        return NULL;
    }
    ht->size = size;

    ht->buckets = calloc(1, sizeof(struct netos_hash_item *) * size);
    if (ht->buckets == NULL) {
        free(ht);
        return NULL;
    }

    for (uint32_t i = 0; i < size; i++) {
        ht->buckets[i] = NULL;
    }
    return ht;
}

void netos_hash_table_free(struct netos_hash_table *ht, void (*callback_free)(void *ptr))
{
    uint32_t i;

    for (i = 0; i < ht->size; i ++) {
        struct netos_hash_item *item;
        struct netos_hash_item *item_next = ht->buckets[i];

        while (item_next) {
            item = item_next;
            if (callback_free) {
                callback_free(item->item);
            }
            item_next = item_next->next;
            free(item);
        }
    }
    free(ht->buckets);
    free(ht);
}

void netos_hash_table_add_item(struct netos_hash_table *ht,
                               void *item,
                               void *key,
                               uint32_t (*callback_hash)(void *key))
{
    uint32_t hash_val = callback_hash(key);
    uint32_t index = hash_val % ht->size;
    struct netos_hash_item *new_item;
    struct netos_hash_item *iter;

    new_item = (struct netos_hash_item *)calloc(1, sizeof(struct netos_hash_item));
    if (new_item == NULL) {
        return;
    }

    new_item->item = item;
    new_item->key = key;
    new_item->next = NULL;

    iter = ht->buckets[index];
    if (!iter) {
        ht->buckets[index] = new_item;
    } else {
        new_item->next = iter;
        ht->buckets[index] = new_item;
    }
}

void* netos_hash_table_search(struct netos_hash_table *ht,
                              void *key,
                              bool (*callback_compare)(void *key1, void *key2),
                              uint32_t (*callback_hash)(void *key))
{
    uint32_t hash_val = callback_hash(key);
    uint32_t index = hash_val % ht->size;
    struct netos_hash_item *iter;

    iter = ht->buckets[index];
    while (iter) {
        if (callback_compare) {
            if (callback_compare(iter->key, key)) {
                return iter->item;
            }
        } else {
            if (iter->key == key) {
                return iter->item;
            }
        }

        iter = iter->next;
    }

    return NULL;
}

void netos_hash_table_for_each(struct netos_hash_table *ht, void (*callback_func)(uint32_t bucket_number, void *item))
{
    struct netos_hash_item *iter;
    uint32_t i;

    for (i = 0; i < ht->size; i++) {
        iter = ht->buckets[i];
        while (iter) {
            callback_func(i, iter->item);
            iter = iter->next;
        }
    }
}

void print_item(uint32_t bucket_number, void *ptr)
{
    struct mac_ip {
        uint8_t mac[6];
        uint32_t ip;
    };

    struct mac_ip *mac_ip = (struct mac_ip *)ptr;
    printf("[%d] mac-ip: %02x:%02x:%02x:%02x:%02x:%02x - %x\n",
           bucket_number,
           mac_ip->mac[0], mac_ip->mac[1], mac_ip->mac[2],
           mac_ip->mac[3], mac_ip->mac[4], mac_ip->mac[5],
           mac_ip->ip);
}

uint32_t hash_mac(void *key)
{
    uint8_t *mac = (uint8_t *)key;
    uint32_t hash_val = 0;
    uint32_t i;

    for (i = 0; i < 6; i++) {
        hash_val += mac[i];
    }
    return hash_val;
}

bool compare_mac(void *key1, void *key2)
{
    uint8_t *mac1 = (uint8_t *)key1;
    uint8_t *mac2 = (uint8_t *)key2;
    uint32_t i;

    for (i = 0; i < 6; i++) {
        if (mac1[i] != mac2[i]) {
            return false;
        }
    }
    return true;
}

#if defined(NETOS_HASH_TABLE_DEBUG)
int main()
{
    struct netos_hash_table *ht = netos_hash_table_init(50);
    struct mac_map {
        uint8_t mac[6];
        uint32_t ip;
    } mac_map_list[] = {
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, 0xc0a80001,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x56}, 0xc0a80002,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x57}, 0xc0a80003,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x58}, 0xc0a80004,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x59}, 0xc0a80005,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x60}, 0xc0a80006,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x61}, 0xc0a80007,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x62}, 0xc0a80008,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x63}, 0xc0a80009,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x64}, 0xc0a80010,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x65}, 0xc0a80011,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x66}, 0xc0a80012,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x67}, 0xc0a80013,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x68}, 0xc0a80014,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x69}, 0xc0a80015,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x70}, 0xc0a80016,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x71}, 0xc0a80017,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x72}, 0xc0a80018,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x73}, 0xc0a80019,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x74}, 0xc0a80020,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x78}, 0xc0a80021,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x79}, 0xc0a80022,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x80}, 0xc0a80023,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x81}, 0xc0a80024,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x82}, 0xc0a80025,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x84}, 0xc0a80026,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x85}, 0xc0a80027,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x86}, 0xc0a80028,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x87}, 0xc0a80029,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x88}, 0xc0a80030,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x89}, 0xc0a80031,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x90}, 0xc0a80032,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x91}, 0xc0a80033,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x92}, 0xc0a80034,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x93}, 0xc0a80035,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x94}, 0xc0a80036,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x95}, 0xc0a80037,
        },
        {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x96}, 0xc0a80038,
        },
    };

    if (ht == NULL) {
        printf("Failed to initialize hash table\n");
        return -1;
    }

    for (uint32_t i = 0; i < sizeof(mac_map_list) / sizeof(mac_map_list[0]); i++) {
        netos_hash_table_add_item(ht, &mac_map_list[i], &mac_map_list[i].mac, hash_mac);
    }

    netos_hash_table_search(ht, &mac_map_list[9].mac, compare_mac, hash_mac);
    netos_hash_table_for_each(ht, print_item);
    netos_hash_table_free(ht, NULL);
    return 0;
}
#endif
