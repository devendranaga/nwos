#include "macsec.h"
#include "event_mgr.h"

namespace netos {

netos_status macsec_hdr::deserialize(packet_buf *pkt_buf)
{
    uint8_t val = pkt_buf->buf_[pkt_buf->offset_];

    /* Short MACsec header. */
    if (pkt_buf->get_remaining_len() < NETOS_MACSEC_HDR_MIN_LEN) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_SHORT_MACSEC_HDR,
                                            event_protocol_level::EVENT_PROTOCOL_L2_MACSEC,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    /* Decode the TCI */
    this->tci.ver   = val & 0x80;
    this->tci.es    = val & 0x40;
    this->tci.sc    = val & 0x20;
    this->tci.scb   = val & 0x10;
    this->tci.e     = val & 0x08;
    this->tci.c     = val & 0x04;
    this->tci.an    = val & 0x03;

    pkt_buf->offset_ ++;

    /* Decode the short length */
    this->short_len = pkt_buf->buf_[pkt_buf->offset_];
    pkt_buf->offset_ ++;

    /* Decode the PN */
    pkt_buf->deserialize_4_bytes(&this->pn);
    if (this->tci.sc) {
        /* If SC is present, then decode the SCI. */
        pkt_buf->deserialize_mac(this->sci.mac);
        pkt_buf->deserialize_2_bytes(&this->sci.port_id);
    }

    this->data_len = pkt_buf->get_remaining_len() - NETOS_MACSEC_ICV_LEN;
    this->data = &pkt_buf->buf_[pkt_buf->offset_];

    /**
     * TCI.E and TCI.S are 0's that means the frame has only ICV.
     *
     * This means decoding the frame further is possible.
     *
     * Lookup for the Ethertype.
     */
    if ((this->tci.e  == 0) && (this->tci.c == 0)) {
        pkt_buf->deserialize_2_bytes(&this->ethertype);
    }

    /* Decode the ICV, ICV is always last bytes - 16. */
    auto icv_off = pkt_buf->len_ - NETOS_MACSEC_ICV_LEN;
    memcpy(this->icv, &pkt_buf->buf_[icv_off], NETOS_MACSEC_ICV_LEN);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status macsec_hdr::serialize(packet_buf *pkt_buf)
{
    pkt_buf->buf_[pkt_buf->offset_] = (this->tci.ver << 7);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->tci.es << 6);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->tci.sc << 5);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->tci.scb << 4);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->tci.e << 3);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->tci.c << 2);
    pkt_buf->buf_[pkt_buf->offset_] |= this->tci.an;

    pkt_buf->offset_ ++;

    pkt_buf->serialize_byte(this->short_len);
    pkt_buf->serialize_4_bytes(this->pn);
    if (this->tci.sc) {
        pkt_buf->serialize_mac(this->sci.mac);
        pkt_buf->serialize_2_bytes(this->sci.port_id);
    }

    pkt_buf->serialize_2_bytes(this->ethertype);

    memcpy(pkt_buf->buf_ + pkt_buf->offset_, this->data, this->data_len);
    pkt_buf->offset_ += this->data_len;

    pkt_buf->serialize_bytes(this->icv, NETOS_MACSEC_ICV_LEN);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

