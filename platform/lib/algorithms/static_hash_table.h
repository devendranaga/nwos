#ifndef PLATFORM_LIB_ALGORITHMS_STATIC_HASH_TABLE_H
#define PLATFORM_LIB_ALGORITHMS_STATIC_HASH_TABLE_H

namespace netos {

namespace lib {

template <typename key_t, typename val_t>
struct static_hash_entry {
    bool used;
    key_t key;
    val_t val;
    struct static_hash_table *next;
};

class static_hash_table {
    public:
        explicit static_hash_table() = default;
        ~static_hash_table() = default;

    private:
};

}

}

#endif

