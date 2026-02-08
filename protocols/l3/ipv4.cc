#include "network_config.h"
#include "ipv4.h"
#include "event_mgr.h"
#include "logging.h"

namespace netos {

uint16_t ipv4_hdr::checksum(packet_buf *pkt_buf)
{
    uint32_t chksum32 = 0;
    uint16_t chksum = 0;
    uint32_t i = 0;

    for (i = this->start_off; i < this->end_off; i += 2) {
        chksum32 += ((pkt_buf->buf_[i + 1] << 8) | (pkt_buf->buf_[i]));
    }

    chksum = ((chksum32 >> 16) + (chksum32 & 0x0000FFFF));

    return chksum;
}

netos_status ipv4_hdr::serialize(packet_buf *pkt_buf)
{
    this->start_off = pkt_buf->offset_;

    pkt_buf->buf_[pkt_buf->offset_] = (this->version << 4);
    pkt_buf->buf_[pkt_buf->offset_] |= this->ihl;
    pkt_buf->offset_ ++;

    pkt_buf->buf_[pkt_buf->offset_] = (this->dscp << 2);
    pkt_buf->buf_[pkt_buf->offset_] |= this->ecn;
    pkt_buf->offset_ ++;

    pkt_buf->serialize_2_bytes(this->total_len);
    pkt_buf->serialize_2_bytes(this->id);
    pkt_buf->buf_[pkt_buf->offset_] = 0;
    if (this->flags.reserved) {
        pkt_buf->buf_[pkt_buf->offset_] |= 0x80;
    }
    if (this->flags.df) {
        pkt_buf->buf_[pkt_buf->offset_] |= 0x40;
    }
    if (this->flags.mf) {
        pkt_buf->buf_[pkt_buf->offset_] |= 0x20;
    }
    pkt_buf->buf_[pkt_buf->offset_] |= (this->frag_off & 0x1F00) >> 8;
    pkt_buf->buf_[pkt_buf->offset_ + 1] = this->frag_off & 0x00FF;
    pkt_buf->offset_ += 2;

    pkt_buf->serialize_byte(this->ttl);
    pkt_buf->serialize_byte(this->protocol);

    this->checksum_off = pkt_buf->offset_;

    pkt_buf->serialize_2_bytes(this->hdr_chksum);
    pkt_buf->serialize_4_bytes(this->src_addr);
    pkt_buf->serialize_4_bytes(this->dst_addr);

    this->end_off = pkt_buf->offset_;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status ipv4_hdr::deserialize(packet_buf *pkt_buf)
{
    network_config *conf = network_config::instance();

    this->version = (pkt_buf->buf_[pkt_buf->offset_] & 0xF0) >> 4;

    /* Invalid IPV4 version. */
    if (this->version != NETOS_IPV4_VERSION) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_IPV4_VERSION,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->ihl = (pkt_buf->buf_[pkt_buf->offset_] & 0x0F);
    pkt_buf->offset_ ++;

    /* Invalid IHL. */
    if (this->ihl < NETOS_IPV4_IHL_DEFAULT) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_SHORT_IPV4_IHL,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->dscp = (pkt_buf->buf_[pkt_buf->offset_] & 0xFC) >> 2;
    this->ecn = (pkt_buf->buf_[pkt_buf->offset_] & 0x03);
    pkt_buf->offset_ ++;

    pkt_buf->deserialize_2_bytes(&this->total_len);
    pkt_buf->deserialize_2_bytes(&this->id);
    this->flags.reserved = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x80);
    this->flags.df = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x40);
    this->flags.mf = !!(pkt_buf->buf_[pkt_buf->offset_] & 0x20);

    /* Reserved bit is set. */
    if (this->flags.reserved) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_IPV4_RESERVED_BIT_SET,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    /* Both DF and MF are set. */
    if (this->flags.df && this->flags.mf) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_IPV4_BOTH_MF_DF_SET,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->frag_off = ((pkt_buf->buf_[pkt_buf->offset_] & 0x0F) << 4);
    this->frag_off |= pkt_buf->buf_[pkt_buf->offset_];
    pkt_buf->offset_ += 2;

    /* Filter->drop_ipv4_fragment and IPv4 header contains fragments. */
    if (conf->filter_config_.drop_ipv4_fragments && (this->frag_off != 0)) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_IPV4_FRAGMENTED_FILTER,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT; 
    }

    pkt_buf->deserialize_byte(&this->ttl);
    if (this->ttl == 0) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_IPV4_TTL_ZERO,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    pkt_buf->deserialize_byte(&this->protocol);

    this->checksum_off = pkt_buf->offset_;
    pkt_buf->deserialize_2_bytes(&this->hdr_chksum);
    pkt_buf->deserialize_4_bytes(&this->src_addr);
    pkt_buf->deserialize_4_bytes(&this->dst_addr);

    /* Checksum is invalid. Malformed. */
    if (this->checksum(pkt_buf) != 0) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_INVAL_IPV4_CHECKSUM,
                                            event_protocol_level::EVENT_PROTOCOL_L3_IPV4,
                                            pkt_buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    this->print();
    return netos_status::NETOS_STATUS_SUCCESS;
}

void ipv4_flags::print()
{
    netos_log_info("\tipv4_flags:\n");
    netos_log_info("\t\t reserved: %d\n", this->reserved);
    netos_log_info("\t\t df: %d\n", this->df);
    netos_log_info("\t\t mf: %d\n", this->mf);
    netos_log_info("\t\t reserved_bits: %d\n", this->reserved_bits);
}

#if defined(NETOS_DEBUG_PKT_DECODE)
void ipv4_hdr::print()
{
    netos_log_info("ipv4_hdr:\n");
    netos_log_info("\t version: %d\n", this->version);
    netos_log_info("\t ihl: %d\n", this->ihl);
    netos_log_info("\t dscp: %d\n", this->dscp);
    netos_log_info("\t ecn: %d\n", this->ecn);
    netos_log_info("\t total_len: %d\n", this->total_len);
    netos_log_info("\t id: %d\n", this->id);
    this->flags.print();
    netos_log_info("\t frag_off: %d\n", this->frag_off);
    netos_log_info("\t ttl: %d\n", this->ttl);
    netos_log_info("\t protocol: %d\n", this->protocol);
    netos_log_info("\t checksum_off: %d\n", this->checksum_off);
    netos_log_info("\t hdr_chksum: 0x%04x\n", this->hdr_chksum);
    netos_log_info("\t src_addr: 0x%x\n", this->src_addr);
    netos_log_info("\t dst_addr: 0x%x\n", this->dst_addr);
}
#else
void ipv4_hdr::print() { }
#endif

}
