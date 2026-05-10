#ifndef LIB_ALGORITHMS_HASH_H
#define LIB_ALGORITHMS_HASH_H

#include <stdio.h>
#include <stdint.h>
#include <functional>

namespace netos {

namespace lib {

template <typename key_t>
using hash_fn = std::function<uint32_t(key_t)>;

template <typename key_t>
using find_fn = std::function<uint32_t(key_t, key_t)>;

template <typename key_t, typename val_t>
using del_fn = std::function<void(key_t, val_t)>;

template <typename key_t, typename val_t>
struct hash_entry {
    bool active;
    key_t key;
    val_t val;
    struct hash_entry *next;
};

template <typename key_t, typename val_t>
class hash_table {
    public:
        explicit hash_table() = default;
        ~hash_table() = default;

        inline int initialize(uint32_t n_buckets,
                       hash_fn<key_t> hfn,
                       find_fn<key_t> ffn,
                       del_fn<key_t, val_t> dfn)
        {
            this->n_buckets_ = n_buckets;
            this->buckets_ = new hash_entry<key_t, val_t>[n_buckets];
            if (!this->buckets_) {
                return -1;
            }

            this->hash_fn_ = hfn;
            this->find_fn_ = ffn;
            this->del_fn_ = dfn;

            for (uint32_t i = 0; i < n_buckets; i ++) {
                this->buckets_[i].active = false;
            }

            return 0;
        }

        inline int add(key_t key, val_t val)
        {
            uint32_t hash_index = this->hash_fn_(key) % this->n_buckets_;
            struct hash_entry<key_t, val_t> *entry = &this->buckets_[hash_index];

            if (entry->active == false) {
                entry->active = true;
                entry->key = key;
                entry->val = val;

                return 0;
            } else {
                struct hash_entry<key_t, val_t> *prev;
                while (entry) {
                    prev = entry;
                    entry = entry->next;
                }
                entry = new hash_entry<key_t, val_t>;
                entry->active = true;
                entry->key = key;
                entry->val = val;
                entry->next = nullptr;
                prev->next = entry;
            }

            return 0;
        }

        inline bool find(key_t key, val_t *val)
        {
            uint32_t hash_index = this->hash_fn_(key) % this->n_buckets_;
            struct hash_entry<key_t, val_t> *entry = &this->buckets_[hash_index];

            if (entry->active) {
                auto res = this->find_fn_(key, entry->key);
                if (res) {
                    *val = entry->val;
                    return true;
                }
            } else {
                while (entry) {
                    if (entry->active) {
                        auto res = this->find_fn_(key, entry->key);
                        if (res) {
                            *val = entry->val;
                            return true;
                        }
                    }
                    entry = entry->next;
                }
            }

            return false;

        }

        inline bool remove(key_t key)
        {
            uint32_t hash_index = this->hash_fn_(key) % this->n_buckets_;
            struct hash_entry<key_t, val_t> *entry = &this->buckets_[hash_index];

            if (entry->active) {
                auto res = this->find_fn_(key, entry->key);
                if (res) {
                    this->del_fn_(entry->key, entry->val);
                    delete entry;
                    entry = entry->next;
                    return true;
                }
            } else {
                struct hash_entry<key_t, val_t> *prev;

                while (entry) {
                    prev = entry;
                    if (entry->active && this->find_fn_(key, entry->key)) {
                        this->del_fn_(entry->key, entry->val);
                        prev->next = entry->next;
                        delete entry;
                        return true;
                    }
                    entry = entry->next;
                }
            }

            return false;

        }

        inline void deinitialize()
        {
            uint32_t i;

            for (i = 0; i < this->n_buckets_; i ++) {
                struct hash_entry<key_t, val_t> *prev;
                struct hash_entry<key_t, val_t> *entry;

                entry = &this->buckets_[i];
                while (entry) {
                    prev = entry;
                    this->del_fn_(entry->key, entry->val);
                    delete entry;
                    entry = entry->next;
                }
            }
        }

    private:
        uint32_t n_buckets_;
        hash_entry<key_t, val_t> *buckets_;
        hash_fn<key_t> hash_fn_;
        find_fn<key_t> find_fn_;
        del_fn<key_t, val_t> del_fn_;
};

}

}

#endif
