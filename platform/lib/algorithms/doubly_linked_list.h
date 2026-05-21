#ifndef PLATFORM_LIB_ALGORITHMS_DOUBLY_LINKED_LIST_H
#define PLATFORM_LIB_ALGORITHMS_DOUBLY_LINKED_LIST_H

#include <functional>

namespace netos {

namespace lib {

template <typename data_t>
using del_fn = std::function<void(data_t)>;

template <typename data_t>
using cmp_fn = std::function<bool(data_t, data_t)>;

template <typename data_t>
using for_each_fn = std::function<void(data_t)>;

template <typename data_t>
struct dll_data {
    data_t          data;
    struct dll_data *prev;
    struct dll_data *next;
};

template <typename data_t>
class doubly_linked_list {
    public:
        explicit doubly_linked_list() = default;
        ~doubly_linked_list() = default;

        void initialize(del_fn<data_t> dfn,
                        cmp_fn<data_t> cmp_fn,
                        for_each_fn<data_t> fwd_fn,
                        for_each_fn<data_t> rvrs_fn);
        int add(data_t data);
        int del(data_t data);
        void for_each_fwd();
        void for_each_rvrs();
        void deinitialize();

    private:
        dll_data<data_t>    *head_;
        dll_data<data_t>    *tail_;
        del_fn<data_t>      dfn_;
        cmp_fn<data_t>      cmp_fn_;
        for_each_fn<data_t> fwd_fn_;
        for_each_fn<data_t> rvrs_fn_;
};

template <typename data_t>
void doubly_linked_list<data_t>::initialize(del_fn<data_t> dfn,
                                            cmp_fn<data_t> cmp_fn,
                                            for_each_fn<data_t> fwd_fn,
                                            for_each_fn<data_t> rvrs_fn)
{
    this->dfn_      = dfn;
    this->cmp_fn_   = cmp_fn;
    this->fwd_fn_   = fwd_fn;
    this->rvrs_fn_  = rvrs_fn;
    this->head_     = nullptr;
    this->tail_     = nullptr;
}

template <typename data_t>
int doubly_linked_list<data_t>::add(data_t data)
{
    dll_data<data_t> *entry = new dll_data<data_t>;

    if (!entry) {
        return -1;
    }

    entry->prev = nullptr;
    entry->next = nullptr;
    entry->data = data;

    if (!this->head_) {
        this->head_ = entry;
        this->tail_ = entry;

        return 0;
    } else {
        this->tail_->next = entry;
        entry->prev = this->tail_;
        this->tail_ = entry;
    }

    return 0;    
}

template <typename data_t>
int doubly_linked_list<data_t>::del(data_t data)
{
    dll_data<data_t> *entry = this->head_;

    if (this->cmp_fn_(entry->data, data)) {
        this->head_ = entry->next;
        if (this->head_) {
            this->head_->prev = nullptr;
        }
        this->dfn_(entry->data);
        delete entry;
        return 0;
    }

    while (entry) {
        if (this->cmp_fn_(entry->data, data)) {
            if (entry->next) {
                entry->prev->next = entry->next;
                entry->next->prev = entry->prev;
            } else {
                this->tail_ = entry->prev;
                this->tail_->next = nullptr;
            }
            this->dfn_(entry->data);
            delete entry;
            return 0;
        }
        entry = entry->next;
    }

    return -1;
}

template <typename data_t>
void doubly_linked_list<data_t>::for_each_fwd()
{
    dll_data<data_t> *entry = this->head_;

    while (entry) {
        this->fwd_fn_(entry->data);
        entry = entry->next;
    }
}

template <typename data_t>
void doubly_linked_list<data_t>::for_each_rvrs()
{
    dll_data<data_t> *entry = this->tail_;

    while (entry) {
        this->rvrs_fn_(entry->data);
        entry = entry->prev;
    }
}

template <typename data_t>
void doubly_linked_list<data_t>::deinitialize()
{
    dll_data<data_t> *entry = this->head_;

    while (entry) {
        dll_data<data_t> *prev = entry;
        entry = entry->next;
        this->dfn_(prev->data);
        delete prev;
    }
}

}

}

#endif

