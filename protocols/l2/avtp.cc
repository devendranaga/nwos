#include <string.h>
#include <arpa/inet.h>

#include "avtp.h"

namespace netos {

netos_status acf_can_header::serialize(packet_buf *pkt_buf)
{
    uint8_t val;
    uint32_t val32;

    val = (this->pad << 6);
    val |= (this->mtv << 5);
    val |= (this->rtr << 4);
    val |= (this->eff << 3);
    val |= (this->brs << 2);
    val |= (this->fdf << 1);
    val |= this->esi;

    pkt_buf->serialize_byte(val);

    val = (this->rsv << 5);
    val |= this->can_bus_id;

    pkt_buf->serialize_byte(val);

    pkt_buf->serialize_8_bytes(this->msg_timestamp);

    val32 = (this->rsv_2 << 29) | (this->can_id);
    pkt_buf->serialize_4_bytes(val32);

    pkt_buf->serialize_bytes(this->can_payload, this->can_msg_len);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status ntscf_header::serialize(packet_buf *pkt_buf)
{
    uint16_t val16 = 0;
    uint32_t val = 0;

    pkt_buf->buf_[pkt_buf->offset_] = (this->opt.sv << 7);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->opt.version << 5);
    pkt_buf->buf_[pkt_buf->offset_] |= (this->opt.r << 3);
    pkt_buf->buf_[pkt_buf->offset_] |= ((this->opt.ntscf_data_len & 0x0700) >> 8);
    pkt_buf->offset_ += 1;

    pkt_buf->buf_[pkt_buf->offset_] = (this->opt.ntscf_data_len & 0x00FF);
    pkt_buf->offset_ += 1;

    pkt_buf->serialize_byte(this->opt.seq_no);

    pkt_buf->serialize_bytes(this->stream_id, AVTP_STREAM_ID_LEN);

    pkt_buf->buf_[pkt_buf->offset_] = this->acf_opt.acf_msg_type << 1;
    if (this->acf_opt.acf_msg_len <= 255) {
        pkt_buf->offset_ ++;

        pkt_buf->buf_[pkt_buf->offset_] = this->acf_opt.acf_msg_len;
        pkt_buf->offset_ ++;
    } else {
        pkt_buf->buf_[pkt_buf->offset_] |= 0x01;
        pkt_buf->offset_ ++;
        pkt_buf->buf_[pkt_buf->offset_] = (this->acf_opt.acf_msg_len & 0xFF);
        pkt_buf->offset_ ++;
    }

    printf("%p %d\n", this->can_hdr, this->acf_opt.acf_msg_type);
    if (this->can_hdr &&
        (this->acf_opt.acf_msg_type == ACF_CAN)) {

        this->can_hdr->serialize(pkt_buf);
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status ntscf_header::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status tscf_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status tscf_header::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status avtp_header::serialize(packet_buf *pkt_buf)
{
    if (this->ntscf_h) {
        pkt_buf->serialize_byte(AVTP_SUBTYPE_NTSCF);
        this->ntscf_h->serialize(pkt_buf);
    }
    if (this->tscf_h) {
        pkt_buf->serialize_byte(AVTP_SUBTYPE_TSCF);
        this->tscf_h->serialize(pkt_buf);
    }
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status avtp_header::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

}

