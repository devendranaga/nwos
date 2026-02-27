#ifndef NETOS_EVENT_INTF_H
#define NETOS_EVENT_INTF_H

#if defined(__cplusplus)
extern "C" {
#endif

#define NETOS_EVENT_INTF_INFO_VERSION 1

/**
 * @brief - Defines Event Interface Info.
 */
struct event_intf_info {
    uint32_t tv_sec;
    uint32_t tv_usec;
    uint32_t event_type;
    uint32_t event_protocol_level;
    uint32_t event_description;
    uint32_t pkt_len;
} __attribute__((packed));

/**
 * @brief - Defines Event Interface Header.
 */
struct event_intf_hdr {
    uint32_t version;
    struct event_intf_info info;
} __attribute__ ((__packed__));

#if defined(__cplusplus)
}
#endif

#endif

