#ifndef __PLATFORM_LIB_ALGORITHMS_QUEUE_IMPL_H__
#define __PLATFORM_LIB_ALGORITHMS_QUEUE_IMPL_H__

#include <iostream>
#include <functional>

namespace netos {

namespace lib {

template <typename type_t>
using lookup_cb = std::function<bool(type_t, type_t)>;

template <typename type_t>
using free_cb = std::function<void(type_t)>;

template <typename type_t>
struct queue {
    bool available;
    type_t item;
    queue *next;
};

template <typename type_t>
class queue_impl {
    public:
        explicit queue_impl(lookup_cb<type_t> lcb): head_(nullptr), tail_(nullptr), lcb_(lcb), items_(0) { }
        ~queue_impl() { }

        int push(type_t item);
        bool pop(type_t *item);
        bool front(type_t *item);
        bool back(type_t *item);
        bool empty();
        uint32_t size();

    private:
        queue<type_t> *head_;
        queue<type_t> *tail_;
        lookup_cb<type_t> lcb_;
        free_cb<type_t> fcb_;
        uint32_t items_;
};

template <typename type_t>
int queue_impl<type_t>::push(type_t item)
{
    queue<type_t> *node;

    node = new queue<type_t>;
    if (!node) {
        return -1;
    }
    node->available = false;
    node->item = item;
    node->next = nullptr;

    if (!this->head_) {
        this->head_ = node;
        this->tail_ = node;
    } else {
        this->tail_->next = node;
        this->tail_ = node;
    }

    this->items_ ++;

    return 0;
}

template <typename type_t>
bool queue_impl<type_t>::pop(type_t *ptr)
{
    queue<type_t> *node = nullptr;

    if (this->head_) {
        node = this->head_;
        *ptr = node->item;

        this->head_ = this->head_->next;
        if (this->head_ == nullptr) {
            this->tail_ = nullptr;
        }

        this->items_ --;
        delete node;

        return true;
    }

    return false;
}

template <typename type_t>
bool queue_impl<type_t>::front(type_t *ptr)
{
    *ptr = nullptr;

    if (this->head_) {
        *ptr = this->head_->item;
        return true;
    }

    return false;
}

template <typename type_t>
bool queue_impl<type_t>::back(type_t *ptr)
{
    *ptr = nullptr;

    printf("tail %p\n", this->tail_);
    if (this->tail_) {
        *ptr = this->tail_->item;
        return true;
    }

    return false;
}

template <typename type_t>
bool queue_impl<type_t>::empty()
{
    return (this->head_ == nullptr);
}

template <typename type_t>
uint32_t queue_impl<type_t>::size()
{
    return this->items_;
}

}

}

#endif

