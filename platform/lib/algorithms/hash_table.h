#ifndef LIB_ALGORITHMS_HASH_H
#define LIB_ALGORITHMS_HASH_H

#include <stdio.h>
#include <stdint.h>
#include <functional>

namespace netos {

namespace lib {

/**
 * @brief - user must implement the hash function with the below function
 *          prototype and must return the 32 bit hash value.
 */
template <typename key_t>
using hash_fn = std::function<uint32_t(key_t)>;

/**
 * @brief - user must set this function and the hash_table passes the key value
 *          user gets his own key value that is passed via hash_table::find().
 */
template <typename key_t>
using find_fn = std::function<bool(key_t, key_t)>;

/**
 * @brief - user must set this function and the hash_table passes the key value
 *          pairs to the callback once the find is success in hash_table::remove().
 */
template <typename key_t, typename val_t>
using del_fn = std::function<void(key_t, val_t)>;

/**
 * @brief - user must set this function and the hash_table pasess the key value
 *          pair in the callback.
 */
template <typename key_t, typename val_t>
using for_each_fn = std::function<bool(key_t, val_t)>;

template <typename key_t, typename val_t>
struct hash_entry {
    key_t               key;
    val_t               val;
    struct hash_entry   *next;
};

template <typename key_t, typename val_t>
class hash_table {
    public:
        explicit hash_table() = default;
        ~hash_table() = default;

        inline int initialize(uint32_t n_buckets,
                       hash_fn<key_t> hfn,
                       find_fn<key_t> ffn,
                       del_fn<key_t, val_t> dfn,
                       for_each_fn<key_t, val_t> fefn)
        {
            this->n_buckets_    = n_buckets;
            this->hash_fn_      = hfn;
            this->find_fn_      = ffn;
            this->del_fn_       = dfn;
            this->fe_fn_        = fefn;

            this->buckets_      = new struct hash_entry<key_t, val_t> *[n_buckets];
            if (!this->buckets_) {
                return -1;
            }

            for (uint32_t i = 0; i < n_buckets; i ++) {
                this->buckets_[i] = nullptr;
            }

            return 0;
        }

        inline int add(key_t key, val_t val)
        {
            uint32_t hash_index = this->hash_fn_(key) % this->n_buckets_;
            struct hash_entry<key_t, val_t> *entry = this->buckets_[hash_index];
            struct hash_entry<key_t, val_t> *prev = nullptr;

            while (entry) {
                prev    = entry;
                entry   = entry->next;
            }

            entry = new hash_entry<key_t, val_t>;
            if (entry) {
                entry->key  = key;
                entry->val  = val;
                entry->next = nullptr;
                if (prev) {
                    prev->next = entry;
                }
                if (!this->buckets_[hash_index]) {
                    this->buckets_[hash_index] = entry;
                }
            } else {
                return -1;
            }

            return 0;
        }

        inline bool find(key_t key, val_t *val)
        {
            uint32_t hash_index = this->hash_fn_(key) % this->n_buckets_;
            struct hash_entry<key_t, val_t> *entry = this->buckets_[hash_index];

            if (this->find_fn_ == nullptr) {
                return false;
            }

            if (entry) {
                auto res = this->find_fn_(key, entry->key);
                if (res) {
                    *val = entry->val;
                    return true;
                }
            } else {
                while (entry) {
                    auto res = this->find_fn_(key, entry->key);
                    if (res) {
                        *val = entry->val;
                        return true;
                    }
                    entry = entry->next;
                }
            }

            return false;
        }

        inline void for_each()
        {
            uint32_t i;

            if (this->fe_fn_ == nullptr) {
                return;
            }

            for (i = 0; i < this->n_buckets_; i ++) {
                struct hash_entry<key_t, val_t> *entry = this->buckets_[i];

                while (entry) {
                    /**
                     * If the for_each callback returns true, that means the caller
                     * asked to stop.
                     */
                    if (this->fe_fn_(entry->key, entry->val) == true) {
                        return;
                    }
                    entry = entry->next;
                }
            }
        }

        inline bool remove(key_t key)
        {
            uint32_t hash_index = this->hash_fn_(key) % this->n_buckets_;
            struct hash_entry<key_t, val_t> *entry = this->buckets_[hash_index];

            if ((this->find_fn_ == nullptr) || (this->del_fn_ == nullptr)) {
                return false;
            }

            if (entry) {
                auto res = this->find_fn_(key, entry->key);
                if (res) {
                    this->del_fn_(entry->key, entry->val);
                    this->buckets_[hash_index] = entry->next;
                    delete entry;
                    return true;
                }
            } else {
                struct hash_entry<key_t, val_t> *prev;

                while (entry) {
                    prev = entry;
                    if (this->find_fn_(key, entry->key)) {
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

            if (this->del_fn_ == nullptr) {
                return;
            }

            for (i = 0; i < this->n_buckets_; i ++) {
                struct hash_entry<key_t, val_t> *prev;
                struct hash_entry<key_t, val_t> *entry;

                entry = this->buckets_[i];
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
        hash_entry<key_t, val_t> **buckets_;
        hash_fn<key_t> hash_fn_;
        find_fn<key_t> find_fn_;
        del_fn<key_t, val_t> del_fn_;
        for_each_fn<key_t, val_t> fe_fn_;
};

}

}

#endif

