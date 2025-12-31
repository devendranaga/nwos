#include "ipv4.h"
#include "event_mgr.h"

namespace netos {

namespace ids {

uint16_t ipv4_hdr::checksum(std::shared_ptr<packet_buf> &pkt_buf)
{
    uint32_t chksum32 = 0;
    uint16_t chksum = 0;
    uint32_t i = 0;

    for (i = this->start_off; i < this->end_off; i += 2) {
        chksum32 += ((pkt_buf->buf_[i + 1] << 8) | (pkt_buf->buf_[i]));
    }

    chksum = ((chksum32 >> 16) | (chksum32));

    return ~chksum;
}

netos_status ipv4_hdr::serialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    this->start_off = pkt_buf->offset_;

    pkt_buf->buf_[pkt_buf->offset_] = (this->version << 4);
    pkt_buf->buf_[pkt_buf->offset_] |= this->ihl;
    pkt_buf->offset_ ++;

    pkt_buf->buf_[pkt_buf->offset_] = (this->dscp << 2);
    pkt_buf->buf_[pkt_buf->offset_] |= this->ecn;
    pkt_buf->offset_ ++;

    pkt_buf->serialize_2_bytes(this->total_len);
    pkt_buf->serialize_2_bytes(this->id);
    pkt_buf->buf_[pkt_buf->offset_] = 0;
    if (this->flags.reserved) {
        pkt_buf->buf_[pkt_buf->offset_] |= 0x80;
    }
    if (this->flags.df) {
        pkt_buf->buf_[pkt_buf->offset_] |= 0x40;
    }
    if (this->flags.mf) {
        pkt_buf->buf_[pkt_buf->offset_] |= 0x20;
    }
    pkt_buf->buf_[pkt_buf->offset_] |= (this->frag_off & 0x0F00) >> 8;
    pkt_buf->buf_[pkt_buf->offset_ + 1] = this->frag_off & 0x00FF;
    pkt_buf->offset_ += 2;

    pkt_buf->serialize_byte(this->ttl);
    pkt_buf->serialize_byte(this->protocol);

    this->checksum_off = pkt_buf->offset_;

    pkt_buf->serialize_2_bytes(this->hdr_chksum);
    pkt_buf->serialize_4_bytes(this->src_addr);
    pkt_buf->serialize_4_bytes(this->dst_addr);

    this->end_off = pkt_buf->offset_;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status ipv4_hdr::deserialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    this->version = (pkt_buf->buf_[pkt_buf->offset_] & 0xF0) >> 4;
    if (this->version != NETOS_IPV4_VERSION) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_IPV4_VERSION,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->ihl = (pkt_buf->buf_[pkt_buf->offset_] & 0x0F);
    pkt_buf->offset_ ++;

    this->dscp = (pkt_buf->buf_[pkt_buf->offset_] & 0xFC) >> 2;
    this->ecn = (pkt_buf->buf_[pkt_buf->offset_] & 0x03);
    pkt_buf->offset_ ++;

    pkt_buf->deserialize_2_bytes(&this->total_len);
    pkt_buf->deserialize_2_bytes(&this->id);
    this->flags.reserved = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x80);
    this->flags.df = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x40);
    this->flags.mf = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x20);
    pkt_buf->offset_ ++;

    this->frag_off = ((pkt_buf->buf_[pkt_buf->offset_] & 0x0F) << 4);
    this->frag_off |= pkt_buf->buf_[pkt_buf->offset_];
    pkt_buf->offset_ += 2;

    pkt_buf->deserialize_byte(&this->ttl);
    pkt_buf->deserialize_byte(&this->protocol);
    pkt_buf->deserialize_2_bytes(&this->hdr_chksum);
    pkt_buf->deserialize_4_bytes(&this->src_addr);
    pkt_buf->deserialize_4_bytes(&this->dst_addr);

    if (this->checksum(pkt_buf) != 0) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

}
