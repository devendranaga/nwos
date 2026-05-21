#include <stdint.h>
#include <stdlib.h>
#include <iostream>

#include "packet_buf.h"
#include "icmpv6.h"
#include "event_mgr.h"

namespace netos {

netos_status icmpv6_echo::serialize(packet_buf *pkt_buf)
{
    pkt_buf->serialize_2_bytes(this->identifier);
    pkt_buf->serialize_2_bytes(this->sequence);
    if (this->data && (this->data_len > 0)) {
        pkt_buf->serialize_bytes(this->data, this->data_len);
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmpv6_hdr::serialize(packet_buf *pkt_buf)
{
    switch (this->type) {
        case NETOS_ICMPV6_ECHO_REQ:
            return this->echo_req.serialize(pkt_buf);
        case NETOS_ICMPV6_ECHO_REPLY:
            return this->echo_reply.serialize(pkt_buf);
    }

    return netos_status::NETOS_STATUS_UNSUPPORTED_ICMPV6_TYPE;
}

netos_status icmpv6_echo::deserialize(packet_buf *pkt_buf)
{
    pkt_buf->deserialize_2_bytes(&this->identifier);
    pkt_buf->deserialize_2_bytes(&this->sequence);

    this->data_len = pkt_buf->len_ - pkt_buf->offset_;
    this->data = (uint8_t *)(pkt_buf->buf_ + pkt_buf->offset_);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmpv6_hdr::deserialize(packet_buf *pkt_buf)
{
    netos_status ret;

    /* check short header length. */
    if ((pkt_buf->offset_ + NETOS_ICMPV6_HDR_LEN) > pkt_buf->len_) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_ICMPV6_SHORT_HDR_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L4_ICMPV6,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->start_off = pkt_buf->offset_;

    pkt_buf->deserialize_byte(&this->type);
    pkt_buf->deserialize_byte(&this->code);
    pkt_buf->deserialize_2_bytes(&this->checksum);

    switch (this->type) {
        case NETOS_ICMPV6_ECHO_REQ:
            if ((pkt_buf->offset_ + NETOS_ICMPV6_ECHO_REQ_HDR_LEN) > pkt_buf->len_) {
                event_mgr::instance()->insert_event(
                                            IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_ICMPV6_ECHO_REQ_SHORT_HDR_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L4_ICMPV6,
                                            pkt_buf->len_);
                return netos_status::NETOS_STATUS_MALFORMED_PKT;
            }

            ret = this->echo_req.deserialize(pkt_buf);
            if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                return ret;
            }
        break;
        case NETOS_ICMPV6_ECHO_REPLY:
            if ((pkt_buf->offset_ + NETOS_ICMPV6_ECHO_REPLY_HDR_LEN) > pkt_buf->len_) {
                event_mgr::instance()->insert_event(
                                            IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_ICMPV6_ECHO_REPLY_SHORT_HDR_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L4_ICMPV6,
                                            pkt_buf->len_);
                return netos_status::NETOS_STATUS_MALFORMED_PKT;
            }

            ret = this->echo_reply.deserialize(pkt_buf);
            if (ret != netos_status::NETOS_STATUS_SUCCESS) {
                return ret;
            }
        break;
        default:
            return netos_status::NETOS_STATUS_MALFORMED_PKT;
        break;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

