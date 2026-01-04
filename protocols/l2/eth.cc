#include <stdint.h>
#include <memory>

#include "eth.h"

namespace netos {

namespace ids {

using namespace netos::lib;

netos_status eth_hdr::serialize(std::shared_ptr<packet_buf> &buf)
{
    buf->serialize_mac(this->dst_mac);
    buf->serialize_mac(this->src_mac);
    buf->serialize_2_bytes(this->ethertype);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status eth_hdr::deserialize(std::shared_ptr<packet_buf> &buf)
{
    if ((buf->len_ - buf->offset_) < NETOS_IDS_ETH_ALEN) {
        return netos_status::NETOS_STATUS_MALFORMED_PKT;
    }

    buf->deserialize_mac(this->dst_mac);
    buf->deserialize_mac(this->src_mac);
    buf->deserialize_2_bytes(&this->ethertype);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

}

