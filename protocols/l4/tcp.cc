#include "tcp.h"
#include "event_mgr.h"
#include "logging.h"

#include <arpa/inet.h>

using namespace netos::ids;

namespace netos {

uint16_t tcp_hdr::checksum(std::shared_ptr<packet_buf> &pkt_buf, uint32_t src_ip, uint32_t dst_ip)
{
    uint32_t chksum32 = 0;
    uint32_t i = 0;

    // Pseudo Header Calculation
    // Source IP
    chksum32 += (src_ip >> 16);
    chksum32 += (src_ip & 0xFFFF);

    // Dest IP
    chksum32 += (dst_ip >> 16);
    chksum32 += (dst_ip & 0xFFFF);

    // Reserved (0) + Protocol (6)
    chksum32 += htons(0x0006);

    // TCP Length
    uint32_t tcp_len = pkt_buf->len_ - this->start_off;
    chksum32 += htons(tcp_len);

    // Payload Checksum
    for (i = this->start_off; i < this->end_off; i += 2) {
        if (i + 1 < pkt_buf->len_) {
            chksum32 += ((pkt_buf->buf_[i + 1] << 8) | (pkt_buf->buf_[i]));
        } else {
            // Odd byte padding
            chksum32 += pkt_buf->buf_[i];
        }
    }

    // Fold 32-bit sum to 16-bit
    while (chksum32 >> 16) {
        chksum32 = (chksum32 & 0xFFFF) + (chksum32 >> 16);
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
    wire_flags |= (this->flags.hl & 0xF) << 12;
    wire_flags |= (this->flags.reserved & 0xF) << 8;
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

    uint16_t wire_flags = 0;
    pkt_buf->deserialize_2_bytes(&wire_flags);

    this->flags.hl = (wire_flags >> 12) & 0xF;
    this->flags.reserved = (wire_flags >> 8) & 0xF;
    this->flags.cwr = (wire_flags >> 7) & 1;
    this->flags.ece = (wire_flags >> 6) & 1;
    this->flags.urg = (wire_flags >> 5) & 1;
    this->flags.ack = (wire_flags >> 4) & 1;
    this->flags.psh = (wire_flags >> 3) & 1;
    this->flags.rst = (wire_flags >> 2) & 1;
    this->flags.syn = (wire_flags >> 1) & 1;
    this->flags.fin = (wire_flags >> 0) & 1;

    pkt_buf->deserialize_2_bytes(&this->win_size);

    this->checksum_off = pkt_buf->offset_;
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
    netos_log_info("\t\t hl: %d\n", this->hl);
    netos_log_info("\t\t reserved: %d\n", this->reserved);
    netos_log_info("\t\t cwr: %d\n", this->cwr);
    netos_log_info("\t\t ece: %d\n", this->ece);
}

#if defined(NETOS_DEBUG_PKT_DECODE)
void tcp_hdr::print()
{
    netos_log_info("tcp_hdr:\n");
    netos_log_info("\t src_port: %d\n", this->src_port);
    netos_log_info("\t dst_port: %d\n", this->dst_port);
    netos_log_info("\t seq_num: %u\n", this->seq_num);
    netos_log_info("\t ack_num: %u\n", this->ack_num);
    netos_log_info("\t win_size: %d\n", this->win_size);
    netos_log_info("\t urg_ptr: %d\n", this->urg_ptr);
    netos_log_info("\t chksum: 0x%04x\n", this->chksum);
    this->flags.print();
}
#else
void tcp_hdr::print() { }
#endif

}
