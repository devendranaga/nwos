#ifndef IDS_EVENT_EVENT_INFO_H
#define IDS_EVENT_EVENT_INFO_H

#include <stdint.h>

namespace netos {

#define IDS_EVENT_TYPE_NONE 0
#define IDS_EVENT_TYPE_ALLOW 1
#define IDS_EVENT_TYPE_DENY 2

enum class event_protocol_level : uint32_t {
    EVENT_PROTOCOL_NONE     = 0x00000000,
    EVENT_PROTOCOL_L2       = 0x00000001,
    EVENT_PROTOCOL_L2_ETH   = 0x00000002,
    EVENT_PROTOCOL_L2_VLAN  = 0x00000003,
    EVENT_PROTOCOL_L2_ARP   = 0x00000004,
    EVENT_PROTOCOL_L3       = 0x00000005,
    EVENT_PROTOCOL_L3_IPV4  = 0x00000007,
    EVENT_PROTOCOL_L3_IPV6  = 0x00000008,
    EVENT_PROTOCOL_L4_TCP   = 0x00000008,
    EVENT_PROTOCOL_L4_UDP   = 0x00000009,
    EVENT_PROTOCOL_L4_ICMP  = 0x0000000A,
};

enum class event_description : uint32_t {
    EVENT_DESC_NONE                                     = 0x00000000,

    EVENT_DESC_SHORT_ETH_HDR_LEN                        = 0x00001000,

    EVENT_DESC_INVAL_VLAN_HDR_LEN                       = 0x00001100,
    EVENT_DESC_INVAL_VLAN_RESERVED                      = 0x00001101,

    EVENT_DESC_INVAL_ARP_HW_TYPE                        = 0x00002001,
    EVENT_DESC_INVAL_ARP_HW_LEN                         = 0x00002002,
    EVENT_DESC_INVAL_ARP_PROTO_TYPE                     = 0x00002003,
    EVENT_DESC_INVAL_ARP_PROTO_LEN                      = 0x00002004,
    EVENT_DESC_INVAL_ARP_OP                             = 0x00002005,
    EVENT_DESC_INVAL_ARP_SENDER_HWADDR                  = 0x00002006,
    EVENT_DESC_INVAL_ARP_SENDER_PROTO_ADDR              = 0x00002007,
    EVENT_DESC_INVAL_ARP_TARGET_PROTO_ADDR              = 0x00002008,

    EVENT_DESC_INVAL_L2_PROTOCOL                        = 0x00002100,
    EVENT_DESC_INVAL_L3_PROTOCOL                        = 0x00002101,
    EVENT_DESC_INVAL_L4_PROTOCOL                        = 0x00002102,

    EVENT_DESC_INVAL_IPV4_VERSION                       = 0x00002200,
    EVENT_DESC_INVAL_IPV4_CHECKSUM                      = 0x00002201,
    EVENT_DESC_SHORT_IPV4_IHL                           = 0x00002202,
    EVENT_DESC_IPV4_RESERVED_BIT_SET                    = 0x00002203,
    EVENT_DESC_IPV4_BOTH_MF_DF_SET                      = 0x00002204,

    /* IPV4 header has fragment and filter config enabled to drop fragments */
    EVENT_DESC_IPV4_FRAGMENTED_FILTER                   = 0x00002205,
    EVENT_DESC_IPV4_TTL_ZERO                            = 0x00002206,

    EVENT_DESC_INVAL_IPV6_VERSION                       = 0x00002302,

    EVENT_DESC_INVAL_TCP_HDR_LEN                        = 0x00002400,
    EVENT_DESC_INVAL_TCP_CHECKSUM                       = 0x00002401,

    EVENT_DESC_INVAL_UDP_HDR_LEN                        = 0x00002500,
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

#endif

