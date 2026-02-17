#ifndef IDS_EVENT_EVENT_INFO_H
#define IDS_EVENT_EVENT_INFO_H

#include <stdint.h>

namespace netos {

/* List of event types. */
#define IDS_EVENT_TYPE_NONE     0
#define IDS_EVENT_TYPE_ALLOW    1
#define IDS_EVENT_TYPE_DENY     2

/**
 * List of protocol levels.
 */
enum class event_protocol_level : uint32_t {
    EVENT_PROTOCOL_NONE         = 0x00000000,
    EVENT_PROTOCOL_L2           = 0x00000001,
    EVENT_PROTOCOL_L2_ETH       = 0x00000002,
    EVENT_PROTOCOL_L2_VLAN      = 0x00000003,
    EVENT_PROTOCOL_L2_ARP       = 0x00000004,
    EVENT_PROTOCOL_L2_MACSEC    = 0x00000005,
    EVENT_PROTOCOL_L3           = 0x00000006,
    EVENT_PROTOCOL_L3_IPV4      = 0x00000007,
    EVENT_PROTOCOL_L3_IPV6      = 0x00000008,
    EVENT_PROTOCOL_L4_TCP       = 0x00000009,
    EVENT_PROTOCOL_L4_UDP       = 0x0000000A,
    EVENT_PROTOCOL_L4_ICMP      = 0x0000000B,
};

/**
 * List of event descriptions.
 */
enum class event_description : uint32_t {
    EVENT_DESC_NONE                                     = 0x00000000,

    /* Short ethernet length. */
    EVENT_DESC_SHORT_ETH_HDR_LEN                        = 0x00001000,

    /* Invalid vlan header length. */
    EVENT_DESC_INVAL_VLAN_HDR_LEN                       = 0x00001100,

    /* Reserved vlan id in the frame. */
    EVENT_DESC_INVAL_VLAN_RESERVED                      = 0x00001101,

    /* Short MACsec header. */
    EVENT_DESC_SHORT_MACSEC_HDR                         = 0x00001200,

    /* Invalid ARP hardware type. */
    EVENT_DESC_INVAL_ARP_HW_TYPE                        = 0x00002001,

    /* Invalid ARP hardware length. */
    EVENT_DESC_INVAL_ARP_HW_LEN                         = 0x00002002,

    /* Invalid ARP protocol type. */
    EVENT_DESC_INVAL_ARP_PROTO_TYPE                     = 0x00002003,

    /* Invalid ARP protocol length. */
    EVENT_DESC_INVAL_ARP_PROTO_LEN                      = 0x00002004,

    /* Invalid ARP operation. */
    EVENT_DESC_INVAL_ARP_OP                             = 0x00002005,

    /* Invalid ARP sender hardware address. */
    EVENT_DESC_INVAL_ARP_SENDER_HWADDR                  = 0x00002006,

    /* Invalid ARP sender protocol address. */
    EVENT_DESC_INVAL_ARP_SENDER_PROTO_ADDR              = 0x00002007,

    /* Invalid ARP target protocol address. */
    EVENT_DESC_INVAL_ARP_TARGET_PROTO_ADDR              = 0x00002008,

    /* Invalid L2 protocol. */
    EVENT_DESC_INVAL_L2_PROTOCOL                        = 0x00002100,

    /* Invalid L3 protocol. */
    EVENT_DESC_INVAL_L3_PROTOCOL                        = 0x00002101,

    /* Invalid L4 protocol. */
    EVENT_DESC_INVAL_L4_PROTOCOL                        = 0x00002102,

    /* Invalid IPV4 version. */
    EVENT_DESC_INVAL_IPV4_VERSION                       = 0x00002200,

    /* Invalid IPV4 checksum. */
    EVENT_DESC_INVAL_IPV4_CHECKSUM                      = 0x00002201,

    /* Short IPV4 header length. */
    EVENT_DESC_SHORT_IPV4_IHL                           = 0x00002202,

    /* Reserved IPV4 bit set. */
    EVENT_DESC_IPV4_RESERVED_BIT_SET                    = 0x00002203,

    /* Both IPV4 MF and DF bits set. */
    EVENT_DESC_IPV4_BOTH_MF_DF_SET                      = 0x00002204,

    /* IPV4 header has fragment and filter config enabled to drop fragments */
    EVENT_DESC_IPV4_FRAGMENTED_FILTER                   = 0x00002205,

    /* IPV4 TTL is zero. */
    EVENT_DESC_IPV4_TTL_ZERO                            = 0x00002206,

    /* IPV4 short header length. */
    EVENT_DESC_IPV4_SHORT_HDR_LEN                       = 0x00002207,

    /* Invalid IPV6 version. */
    EVENT_DESC_INVAL_IPV6_VERSION                       = 0x00002302,

    /* Invalid TCP header length. */
    EVENT_DESC_INVAL_TCP_HDR_LEN                        = 0x00002400,

    /* Invalid TCP checksum. */
    EVENT_DESC_INVAL_TCP_CHECKSUM                       = 0x00002401,

    /* Invalid UDP header length. */
    EVENT_DESC_INVAL_UDP_HDR_LEN                        = 0x00002500,

    /* Invalid ICMP checksum. */
    EVENT_DESEC_INVAL_ICMP_CHECKSUM                     = 0x00002600,
};

/**
 * Event information structure.
 */
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

