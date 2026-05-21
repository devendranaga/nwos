#include "lldp_hdr.h"

namespace netos {

netos_status lldp_tlv_chassis_id::deserialize(uint8_t len, packet_buf *pkt_buf)
{
    if (len != LLDP_TLV_TYPE_CHASSIS_SUBTYPE_MACADDR_LEN) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->chassis_subtype);
    pkt_buf->deserialize_mac(this->chassis_id);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status lldp_tlv_port_id::deserialize(uint8_t len, packet_buf *pkt_buf)
{
    if (len != LLDP_TLV_TYPE_PORT_ID_LEN) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->port_id_subtype);
    this->port_id = (pkt_buf->buf_[pkt_buf->offset_ + 2] << 16) |
                    (pkt_buf->buf_[pkt_buf->offset_ + 1] << 8) |
                    (pkt_buf->buf_[pkt_buf->offset_]);
    pkt_buf->offset_ += 3;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status lldp_tlv_ttl::deserialize(uint8_t len, packet_buf *pkt_buf)
{
    if (len != LLDP_TLV_TYPE_TTL_ID_LEN) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_2_bytes(&this->seconds);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status lldp_hdr::deserialize(packet_buf *pkt_buf)
{
    netos_status ret = netos_status::NETOS_STATUS_SUCCESS;

    while ((pkt_buf->offset_ > pkt_buf->len_) && (ret == NETOS_STATUS_SUCCESS)) {
        uint8_t type;
        uint8_t len;

        type = (pkt_buf->buf_[pkt_buf->offset_] & 0xFE) >> 1;
        len = ((pkt_buf->buf_[pkt_buf->offset_] & 0x01) << 8) |
               (pkt_buf->buf_[pkt_buf->offset_ + 1]);
        pkt_buf->offset_ += 2;

        switch (type) {
            case LLDP_TLV_TYPE_CHASSIS_ID:
                ret = this->chassis_id.deserialize(len, pkt_buf);
                if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                    this->valid_ids |= LLDP_ID_VALID_CHASSIS;
                }
            break;
            case LLDP_TLV_TYPE_PORT_ID:
                ret = this->port_id.deserialize(len, pkt_buf);
                if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                    this->valid_ids |= LLDP_ID_VALID_PORT_ID;
                }
            break;
            case LLDP_TLV_TYPE_TTL_ID:
                ret = this->ttl.deserialize(len, pkt_buf);
                if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                    this->valid_ids |= LLDP_ID_VALID_TTL;
                }
            break;
            default:
            return netos_status::NETOS_STATUS_MALFORMED_PKT;
        }
    }

    return ret;
}

}

