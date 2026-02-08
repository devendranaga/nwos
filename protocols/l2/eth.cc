#include <stdint.h>
#include <memory>

#include "eth.h"
#include "event_mgr.h"
#include "logging.h"

namespace netos {

using namespace netos::lib;

netos_status eth_hdr::serialize(packet_buf *buf)
{
    buf->serialize_mac(this->dst_mac);
    buf->serialize_mac(this->src_mac);
    buf->serialize_2_bytes(this->ethertype);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status eth_hdr::deserialize(packet_buf *buf)
{
    if ((buf->len_ - buf->offset_) < NETOS_ETH_ALEN) {
        event_mgr::instance()->insert_event(IDS_EVENT_TYPE_DENY,
                                            event_description::EVENT_DESC_SHORT_ETH_HDR_LEN,
                                            event_protocol_level::EVENT_PROTOCOL_L2_ETH,
                                            buf->len_);
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    buf->deserialize_mac(this->dst_mac);
    buf->deserialize_mac(this->src_mac);
    buf->deserialize_2_bytes(&this->ethertype);

    this->print();
    return netos_status::NETOS_STATUS_SUCCESS;
}

#if defined(NETOS_DEBUG_PKT_DECODE)
void eth_hdr::print()
{
    netos_log_info("eth_hdr:\n");
    netos_log_info("\t dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            this->dst_mac[0], this->dst_mac[1], this->dst_mac[2],
                            this->dst_mac[3], this->dst_mac[4], this->dst_mac[5]);
    netos_log_info("\t src: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            this->src_mac[0], this->src_mac[1], this->src_mac[2],
                            this->src_mac[3], this->src_mac[4], this->src_mac[5]);
    netos_log_info("\t ethertype: 0x%04x\n", this->ethertype);
}
#else
void eth_hdr::print() { }
#endif

}

