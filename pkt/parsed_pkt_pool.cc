#include <parsed_pkt.h>

namespace netos {

netos_status parsed_pkt_pool::initialize(uint32_t size)
{
    uint32_t i;

    this->size_ = size;

    for (i = 0; i < size; i ++) {
        parsed_pkt *pkt;
        netos_status status;

        pkt = (parsed_pkt *)calloc(1, sizeof(parsed_pkt));
        if (!pkt) {
            return netos_status::NETOS_STATUS_ALLOC_FAILURE;
        }

        pkt->pkt_buf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pkt->pkt_buf) {
            free(pkt);
            return netos_status::NETOS_STATUS_ALLOC_FAILURE;
        }

        status = pkt->pkt_buf->allocate();
        if (status != netos_status::NETOS_STATUS_SUCCESS) {
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

    if (!this->head_) {
        return nullptr;
    }

    pkt = this->head_;
    this->head_ = this->head_->next;

    return pkt;
}

void parsed_pkt_pool::put_pkt(parsed_pkt *pkt)
{
    if (!pkt) {
        return;
    }

    pkt->next = this->head_;
    this->head_ = pkt;
}

}