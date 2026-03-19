#include "udp.h"
#include "event_mgr.h"

namespace netos {

netos_status udp_hdr::serialize(packet_buf *pkt_buf)
{
    pkt_buf->serialize_2_bytes(this->src_port);
    pkt_buf->serialize_2_bytes(this->dst_port);
    pkt_buf->serialize_2_bytes(this->len);
    pkt_buf->serialize_2_bytes(this->checksum);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status udp_hdr::deserialize(packet_buf *pkt_buf)
{
    if ((pkt_buf->len_ - pkt_buf->offset_) < NETOS_UDP_HDR_LEN_DEFAULT) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_UDP_HDR_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L4_UDP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->start_off = pkt_buf->offset_;

    pkt_buf->deserialize_2_bytes(&this->src_port);
    pkt_buf->deserialize_2_bytes(&this->dst_port);

    if (this->src_port == this->dst_port) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_2_bytes(&this->len);

    if (this->len == 0) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_2_bytes(&this->checksum);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

