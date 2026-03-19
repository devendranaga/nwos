#include <parsed_pkt.h>

namespace netos {

netos_status parsed_pkt_pool::initialize(uint32_t size)
{
    uint32_t i;

    this->size_ = size;

    /* Allocate pool pointer first. */
    this->packet_pool_ptr_ = (uint8_t *)calloc(1, NETOS_PACKET_BUF_SIZE * size);
    if (!this->packet_pool_ptr_) {
        return netos_status::NETOS_STATUS_ALLOC_FAILURE;
    }

    for (i = 0; i < size; i ++) {
        parsed_pkt *pkt;
        netos_status status;

        pkt = (parsed_pkt *)calloc(1, sizeof(parsed_pkt));
        if (!pkt) {
            return netos_status::NETOS_STATUS_ALLOC_FAILURE;
        }

        pkt->ref_count = 0;

        pkt->pkt_buf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pkt->pkt_buf) {
            free(pkt);
            return netos_status::NETOS_STATUS_ALLOC_FAILURE;
        }

        pkt->pkt_buf->buf_ = (uint8_t *)(this->packet_pool_ptr_ + (i * NETOS_PACKET_BUF_SIZE));
        if (!pkt->pkt_buf->buf_) {
            free(pkt->pkt_buf);
            free(pkt);
            return status;
        }

        if (!this->head_) {
            this->head_ = pkt;
        } else {
            pkt->next = this->head_;
            this->head_ = pkt;
        }
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

parsed_pkt *parsed_pkt_pool::get_pkt()
{
    parsed_pkt *pkt;

    std::unique_lock<std::mutex> l(this->lock_);

    if (!this->head_) {
        return nullptr;
    }

    pkt = this->head_;
    this->head_ = this->head_->next;

    // Initialize packet state before incrementing ref_count
    pkt->pkt_buf->offset_ = 0;
    pkt->pkt_buf->len_ = 0;
    pkt->ref_count.store(1, std::memory_order_relaxed);  // Set to 1 instead of incrementing from unknown value

    return pkt;
}

void parsed_pkt_pool::put_pkt(parsed_pkt *pkt)
{
    if (!pkt) {
        return;
    }

    // Use fetch_sub to get the previous value atomically
    uint32_t prev_count = pkt->ref_count.fetch_sub(1, std::memory_order_acq_rel);

    // Only return to pool when ref_count reaches 0 (prev_count was 1)
    if (prev_count == 1) {
        std::unique_lock<std::mutex> l(this->lock_);
        pkt->pkt_buf->offset_ = 0;
        pkt->pkt_buf->len_ = 0;
        pkt->ref_count.store(0, std::memory_order_relaxed);  // Reset to 0

        pkt->next = this->head_;
        this->head_ = pkt;
    }
}

}
