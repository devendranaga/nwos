#include "ipv6.h"
#include "event_mgr.h"
#include <cstring>

namespace netos {

netos_status ipv6_hdr::serialize(packet_buf *pkt_buf)
{
    this->start_off = pkt_buf->offset_;

    // Serialize Version, Traffic Class, and Flow Label (32 bits total)
    // Layout:
    // 0       4       8       12      16      20      24      28      31
    // |-------|-------|-------|-------|-------|-------|-------|-------|
    // |Ver(4) | TrCls(8)      | Flow Label(20)                        |
    
    uint32_t first_word = 0;

    first_word |= (static_cast<uint32_t>(this->version) & 0xF) << 28;
    first_word |= (static_cast<uint32_t>(this->traffic_class) & 0xFF) << 20;
    first_word |= (static_cast<uint32_t>(this->flow_label) & 0xFFFFF);

    // Manual Network Byte Order serialization
    pkt_buf->buf_[pkt_buf->offset_ + 0] = (first_word >> 24) & 0xFF;
    pkt_buf->buf_[pkt_buf->offset_ + 1] = (first_word >> 16) & 0xFF;
    pkt_buf->buf_[pkt_buf->offset_ + 2] = (first_word >> 8) & 0xFF;
    pkt_buf->buf_[pkt_buf->offset_ + 3] = (first_word) & 0xFF;
    pkt_buf->offset_ += 4;

    pkt_buf->serialize_2_bytes(this->payload_len);
    pkt_buf->serialize_byte(this->nh);
    pkt_buf->serialize_byte(this->hop_limit);

    pkt_buf->serialize_bytes(this->src_addr, 16);
    pkt_buf->serialize_bytes(this->dst_addr, 16);

    this->end_off = pkt_buf->offset_;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status ipv6_hdr::deserialize(packet_buf *pkt_buf)
{
    uint32_t first_word = 0;

    // Manual Network Byte Order deserialization
    first_word  = (uint32_t)pkt_buf->buf_[pkt_buf->offset_ + 0] << 24;
    first_word |= (uint32_t)pkt_buf->buf_[pkt_buf->offset_ + 1] << 16;
    first_word |= (uint32_t)pkt_buf->buf_[pkt_buf->offset_ + 2] << 8;
    first_word |= (uint32_t)pkt_buf->buf_[pkt_buf->offset_ + 3];
    pkt_buf->offset_ += 4;

    this->version = (first_word >> 28) & 0xF;

    if (this->version != NETOS_IPV6_VERSION) {
         event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_IPV6_VERSION,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV6,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->traffic_class = (first_word >> 20) & 0xFF;
    this->flow_label = first_word & 0xFFFFF;

    pkt_buf->deserialize_2_bytes(&this->payload_len);
    pkt_buf->deserialize_byte(&this->nh);
    pkt_buf->deserialize_byte(&this->hop_limit);

    pkt_buf->deserialize_bytes(this->src_addr, NETOS_IPV6_ADDR_LEN);
    pkt_buf->deserialize_bytes(this->dst_addr, NETOS_IPV6_ADDR_LEN);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}
