#include "ieee8021br.h"

namespace netos {

netos_status ieee8021br_hdr::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status ieee8021br_hdr::deserialize(packet_buf *pkt_buf)
{
    uint8_t val;

    if ((pkt_buf->offset_ + NETOS_IEEE8021BR_HDR_LEN) > pkt_buf->len_) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&val);
    this->e_pcp = (val & 0xE0) >> 5;
    this->e_dei = !!(val & 0x10);
    this->ingress_ecid_base = ((val & 0x0F) << 8);

    pkt_buf->deserialize_byte(&val);
    this->ingress_ecid_base |= val;

    pkt_buf->deserialize_byte(&val);
    this->reserved = (val & 0xC0) >> 6;
    this->grp = (val & 0x30) >> 4;
    this->ecid_base = ((val & 0x0F) << 8);

    pkt_buf->deserialize_byte(&val);
    this->ecid_base |= val;

    pkt_buf->deserialize_byte(&this->target_ecid);
    pkt_buf->deserialize_byte(&this->ecid_ext);
    pkt_buf->deserialize_2_bytes(&this->ethertype);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

