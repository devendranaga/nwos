#ifndef IDS_EVENT_EVENT_INFO_H
#define IDS_EVENT_EVENT_INFO_H

#include <stdint.h>

namespace netos {

namespace ids {

#define IDS_EVENT_TYPE_NONE 0
#define IDS_EVENT_TYPE_ALLOW 1
#define IDS_EVENT_TYPE_DENY 2

enum class event_protocol_level : uint32_t {
    EVENT_PROTOCOL_NONE     = 0x00000000,
    EVENT_PROTOCOL_L2_ETH   = 0x00000001,
    EVENT_PROTOCOL_L2_ARP   = 0x00000002,
};

enum class event_description : uint32_t {
    EVENT_DESC_NONE                 = 0x00000000,
    EVENT_DESC_INVAL_ARP_HW_TYPE    = 0x00002001,
};

struct event_info {
    uint8_t                 event_type;
    event_description       event_desc;
    event_protocol_level    protocol_level;
    uint32_t                pkt_len;

    explicit event_info() : event_type(IDS_EVENT_TYPE_NONE),
                            event_desc(event_description::EVENT_DESC_NONE),
                            protocol_level(event_protocol_level::EVENT_PROTOCOL_NONE),
                            pkt_len(0)
    {
    }
    ~event_info()
    {
    }
};

}

}

#endif

