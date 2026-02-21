#include "mka.h"

using namespace netos::lib;

namespace netos {

netos_status ieee8021x_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_header::serialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status mka_header::deserialize(packet_buf *pkt_buf)
{
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status ieee8021x_header::deserialize(packet_buf *pkt_buf)
{
    pkt_buf->deserialize_byte(&this->version);
    pkt_buf->deserialize_byte(&this->type);
    pkt_buf->deserialize_2_bytes(&this->len);

    if (this->type == IEEE8021X_TYPE_MKA) {
        this->mh.deserialize(pkt_buf);
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

}


