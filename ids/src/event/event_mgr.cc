#include "event_mgr.h"

namespace netos {

namespace ids {

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

    evt_q_lock_.lock();
    event_info_queue_.push(evt_info);
    evt_q_lock_.unlock();
}

}

}

