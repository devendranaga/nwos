#include "tcp.h"
#include "event_mgr.h"
#include "logging.h"

#include <arpa/inet.h>

namespace netos {

uint16_t tcp_hdr::checksum(std::shared_ptr<packet_buf> &pkt_buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    uint32_t chksum32 = 0;
    uint32_t i = 0;
    uint32_t pad = 0;

    if ((pkt_buf->len_ - this->start_off) % 2) {
        pad = 1;
    }

    for (i = 0; i < 4; i += 2) {
        chksum32 += (src_ip[i + 1] << 8) + src_ip[i];
    }

    for (i = 0; i < 4; i += 2) {
        chksum32 += (dst_ip[i + 1] << 8) + dst_ip[i];
    }

    // TCP Length
    uint32_t tcp_len = pkt_buf->len_ - this->start_off;

    chksum32 += (tcp_len & 0x0000FFFFu) + ((tcp_len & 0xFFFF0000u) >> 16);

    // Reserved (0) + Protocol (6)
    chksum32 += 0x0006;

    // Payload Checksum
    for (i = this->start_off; i <= pkt_buf->len_ + pad; i += 2) {
        if (i < pkt_buf->len_ - 1) {
            chksum32 += ((pkt_buf->buf_[i] << 8) | (pkt_buf->buf_[i + 1]));
        } else {
            // Odd byte padding
            chksum32 += pkt_buf->buf_[i] << 8;
        }
    }

    // Fold 32-bit sum to 16-bit
    if (chksum32 > 0xFFFFu) {
        chksum32 = ((chksum32 & 0xFFFF0000) >> 16) + (chksum32 & 0x0000FFFF);
    }

    return ~chksum32;
}

netos_status tcp_hdr::serialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    this->start_off = pkt_buf->offset_;

    pkt_buf->serialize_2_bytes(this->src_port);
    pkt_buf->serialize_2_bytes(this->dst_port);
    pkt_buf->serialize_4_bytes(this->seq_num);
    pkt_buf->serialize_4_bytes(this->ack_num);

    uint16_t wire_flags = 0;
    wire_flags |= (this->hl & 0xF) << 12;
    wire_flags |= (this->flags.cwr & 1) << 7;
    wire_flags |= (this->flags.ece & 1) << 6;
    wire_flags |= (this->flags.urg & 1) << 5;
    wire_flags |= (this->flags.ack & 1) << 4;
    wire_flags |= (this->flags.psh & 1) << 3;
    wire_flags |= (this->flags.rst & 1) << 2;
    wire_flags |= (this->flags.syn & 1) << 1;
    wire_flags |= (this->flags.fin & 1) << 0;

    pkt_buf->serialize_2_bytes(wire_flags);

    pkt_buf->serialize_2_bytes(this->win_size);

    this->checksum_off = pkt_buf->offset_;
    pkt_buf->serialize_2_bytes(0); // Zero out checksum for calculation

    pkt_buf->serialize_2_bytes(this->urg_ptr);

    this->end_off = pkt_buf->offset_;

    pkt_buf->buf_[this->checksum_off] = (this->chksum & 0x00FF);
    pkt_buf->buf_[this->checksum_off + 1] = (this->chksum & 0xFF00) >> 8;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status tcp_hdr::deserialize(std::shared_ptr<packet_buf> &pkt_buf)
{
    if (pkt_buf->len_ < NETOS_TCP_HLEN_MIN) {
         event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_TCP_HDR_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L4_TCP,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->start_off = pkt_buf->offset_;

    pkt_buf->deserialize_2_bytes(&this->src_port);
    pkt_buf->deserialize_2_bytes(&this->dst_port);
    pkt_buf->deserialize_4_bytes(&this->seq_num);
    pkt_buf->deserialize_4_bytes(&this->ack_num);

    this->hl = (pkt_buf->buf_[pkt_buf->offset_] & 0xF0) >> 4;
    this->flags.ecn = (pkt_buf->buf_[pkt_buf->offset_] & 0x01);
    pkt_buf->offset_ ++;

    this->flags.cwr = (pkt_buf->buf_[pkt_buf->offset_] & 0x80) >> 7;
    this->flags.ece = (pkt_buf->buf_[pkt_buf->offset_] & 0x40) >> 6;
    this->flags.urg = (pkt_buf->buf_[pkt_buf->offset_] & 0x20) >> 5;
    this->flags.ack = (pkt_buf->buf_[pkt_buf->offset_] & 0x10) >> 4;
    this->flags.psh = (pkt_buf->buf_[pkt_buf->offset_] & 0x08) >> 3;
    this->flags.rst = (pkt_buf->buf_[pkt_buf->offset_] & 0x04) >> 2;
    this->flags.syn = (pkt_buf->buf_[pkt_buf->offset_] & 0x02) >> 1;
    this->flags.fin = (pkt_buf->buf_[pkt_buf->offset_] & 0x01) >> 0;
    pkt_buf->offset_ ++;

    pkt_buf->deserialize_2_bytes(&this->win_size);

    pkt_buf->deserialize_2_bytes(&this->chksum);

    pkt_buf->deserialize_2_bytes(&this->urg_ptr);

    this->end_off = pkt_buf->offset_;

    this->print();
    return netos_status::NETOS_STATUS_SUCCESS;
}

void tcp_flags::print()
{
    netos_log_info("\t flags:\n");
    netos_log_info("\t\t urg: %d\n", this->urg);
    netos_log_info("\t\t ack: %d\n", this->ack);
    netos_log_info("\t\t psh: %d\n", this->psh);
    netos_log_info("\t\t rst: %d\n", this->rst);
    netos_log_info("\t\t syn: %d\n", this->syn);
    netos_log_info("\t\t fin: %d\n", this->fin);
}

#if defined(NETOS_DEBUG_PKT_DECODE)
void tcp_hdr::print()
{
    netos_log_info("tcp_hdr:\n");
    netos_log_info("\t src_port: %d\n", this->src_port);
    netos_log_info("\t dst_port: %d\n", this->dst_port);
    netos_log_info("\t seq_num: %u\n", this->seq_num);
    netos_log_info("\t ack_num: %u\n", this->ack_num);
    netos_log_info("\t hl: %d\n", this->hl);
    netos_log_info("\t win_size: %d\n", this->win_size);
    netos_log_info("\t urg_ptr: %d\n", this->urg_ptr);
    netos_log_info("\t chksum: 0x%04x\n", this->chksum);
    this->flags.print();
}
#else
void tcp_hdr::print() { }
#endif

}
