#ifndef NETOS_EVENT_INTF_H
#define NETOS_EVENT_INTF_H

#if defined(__cplusplus)
extern "C" {
#endif

struct event_intf {
    uint32_t version;
    uint32_t event_type;
    uint32_t event_protocol_level;
    uint32_t event_description;
    uint32_t pkt_len;
} __attribute__((packed));

#if defined(__cplusplus)
}
#endif

#endif
