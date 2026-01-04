#include "vlan.h"
#include "event_mgr.h"

namespace netos {

namespace ids {

netos_status vlan_hdr::serialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    pkt_buf->buf_[pkt_buf->offset_] = 0;
    pkt_buf->buf_[pkt_buf->offset_] |= (this->priority << 5);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->dei << 4);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->vid & 0x0F00) >> 8;
    pkt_buf->offset_ ++;

    pkt_buf->buf_[pkt_buf->offset_] = this->vid & 0x00FF;
    pkt_buf->offset_ ++;

    pkt_buf->serialize_2_bytes(this->ethertype);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status vlan_hdr::deserialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    if ((pkt_buf->len_ - pkt_buf->offset_) > NETOS_IDS_VLAN_HDR_LEN) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_VLAN_HDR_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L2_VLAN,
                                            pkt_buf->len_);
    }
    this->priority = (pkt_buf->buf_[pkt_buf->offset_] >> 5);
    this->dei = (pkt_buf->buf_[pkt_buf->offset_] & 0x10) >> 4;
    this->vid = ((pkt_buf->buf_[pkt_buf->offset_] & 0x0F) << 8) |
                 pkt_buf->buf_[pkt_buf->offset_ + 1];
    pkt_buf->offset_ += 2;

    pkt_buf->deserialize_2_bytes(&this->ethertype);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

}
