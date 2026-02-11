#include <icmp.h>

namespace netos {

netos_status icmp_echo::serialize(packet_buf *pkt_buf)
{
    pkt_buf->serialize_2_bytes(this->identifier);
    pkt_buf->serialize_2_bytes(this->sequence_number);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_hdr::serialize(packet_buf *pkt_buf)
{
    uint16_t checksum;

    this->start_off = pkt_buf->offset_;

    this->start_off = pkt_buf->offset_;

    pkt_buf->serialize_byte(this->type);
    pkt_buf->serialize_byte(this->code);
    this->checksum_off = pkt_buf->offset_;
    pkt_buf->serialize_2_bytes(0);

    switch (this->type) {
        case static_cast<uint8_t>(icmp_type::ECHO_REPLY):
            this->echo_reply->serialize(pkt_buf);
        break;
        case static_cast<uint8_t>(icmp_type::ECHO_REQUEST):
            this->echo_request->serialize(pkt_buf);
        break;
        default:
            return netos_status::NETOS_STATUS_UNSUPPORTED_ICMP_TYPE;
    }

    this->end_off = pkt_buf->offset_;

    checksum = this->calc_checksum(pkt_buf);
    pkt_buf->buf_[this->checksum_off] = checksum & 0xFF;
    pkt_buf->buf_[this->checksum_off + 1] = (checksum & 0xFF00) >> 8;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_dest_unreachable::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_time_exceeded::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_parameter_problem::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_source_quench::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_redirect::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

uint16_t icmp_hdr::calc_checksum(packet_buf *pkt_buf)
{
    uint32_t checksum = 0;
    uint32_t i = 0;
    uint32_t pad = 0;

    if ((this->end_off - this->start_off) % 2) {
        pad = 1;
    }

    for (i = this->start_off; i <= this->end_off + pad; i += 2) {
        checksum += (pkt_buf->buf_[i + 1] << 8) | pkt_buf->buf_[i];
    }

    if (checksum > 0xFFFFu) {
        checksum = ((checksum & 0xFFFF0000) >> 16) + (checksum & 0xFFFF);
    }

    checksum = ~checksum;

    return checksum;
}

netos_status icmp_hdr::verify_checksum(packet_buf *pkt_buf)
{
    uint16_t checksum;

    checksum = this->calc_checksum(pkt_buf);
    if (checksum != 0) {
        return netos_status::NETOS_STATUS_INVAL_ICMP_CHECKSUM;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_echo::deserialize(packet_buf *pkt_buf)
{
    pkt_buf->deserialize_2_bytes(&this->identifier);
    pkt_buf->deserialize_2_bytes(&this->sequence_number);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_timestamp::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_identification::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status icmp_hdr::deserialize(packet_buf *pkt_buf)
{
    netos_status ret;

    this->start_off = pkt_buf->offset_;
    this->end_off = pkt_buf->len_;

    pkt_buf->deserialize_byte(&this->type);
    pkt_buf->deserialize_byte(&this->code);
    pkt_buf->deserialize_2_bytes(&this->checksum);

    switch (this->type) {
        case static_cast<uint32_t>(icmp_type::ECHO_REPLY):
            this->echo_reply = std::make_shared<icmp_echo>();
            this->echo_reply->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::DEST_UNREACHABLE):
            this->dest_unreachable = std::make_shared<icmp_dest_unreachable>();
            this->dest_unreachable->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::SOURCE_QUENCH):
            this->source_quench = std::make_shared<icmp_source_quench>();
            this->source_quench->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::REDIRECT_MSG):
            this->redirect = std::make_shared<icmp_redirect>();
            this->redirect->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::ECHO_REQUEST):
            this->echo_request = std::make_shared<icmp_echo>();
            this->echo_request->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::TIME_EXCEEDED):
            this->time_exceeded = std::make_shared<icmp_time_exceeded>();
            this->time_exceeded->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::PARAMETER_PROBLEM):
            this->param_problem = std::make_shared<icmp_parameter_problem>();
            this->param_problem->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::TIMESTAMP):
            this->timestamp = std::make_shared<icmp_timestamp>();
            this->timestamp->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::TIMESTAMP_REPLY):
            this->timestamp_reply = std::make_shared<icmp_timestamp>();
            this->timestamp_reply->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::IDENTIFICATION_REQ):
            this->identification_req = std::make_shared<icmp_identification>();
            this->identification_req->deserialize(pkt_buf);
        break;
        case static_cast<uint32_t>(icmp_type::IDENTIFICATION_REPLY):
            this->identification_reply = std::make_shared<icmp_identification>();
            this->identification_reply->deserialize(pkt_buf);
        break;
        default:
            return netos_status::NETOS_STATUS_UNSUPPORTED_ICMP_TYPE;
    }

    ret = this->verify_checksum(pkt_buf);
    /* Raise if checksum is invalid. */
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESEC_INVAL_ICMP_CHECKSUM,
                                            event_protocol_level::EVENT_PROTOCOL_L4_ICMP,
                                            pkt_buf->len_);
        return ret;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

}
