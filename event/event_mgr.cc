#include "event_mgr.h"

namespace netos {

void event_mgr::insert_event(uint8_t event_type,
                             event_description desc,
                             event_protocol_level proto_level,
                             uint32_t pkt_len)
{
    event_info evt_info;

    evt_info.event_type = event_type;
    evt_info.event_desc = desc;
    evt_info.protocol_level = proto_level;
    evt_info.pkt_len = pkt_len;

    std::unique_lock<std::mutex> l(this->evt_q_lock_);
    event_info_queue_.push(evt_info);
}

}

