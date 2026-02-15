#include "macsec.h"

namespace netos {

netos_status macsec_hdr::deserialize(packet_buf *pkt_buf)
{
    netos_status ret;
    uint8_t val = pkt_buf->buf_[pkt_buf->offset_];

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

    /* Decode the ICV, ICV is always last bytes - 16. */
    auto icv_off = pkt_buf->len_ - NETOS_MACSEC_IV_LEN;
    pkt_buf->deserialize_bytes(this->iv, icv_off);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status macsec_hdr::serialize(packet_buf *buf)
{
    netos_status ret;

    return netos_status::NETOS_STATUS_SUCCESS;
}

}
