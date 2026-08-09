#ifndef NETOS_EVENT_MSG_H
#define NETOS_EVENT_MSG_H

#define NETOS_EVENT_MSG_HDR_MAGIC   0x4E574F53
#define NETOS_EVENT_MSG_VERSION     1

typedef struct __attribute__ ((__packed__)) {
    uint16_t    src_port;
    uint16_t    dst_port;
} netos_event_l4_tcp_udp_t;

typedef struct __attribute__ ((__packed__)) {
    uint8_t     type;
    uint8_t     code;
} netos_event_icmp_t;

typedef struct __attribute__ ((__packed__)) {
    uint32_t    src_ipaddr;
    uint32_t    dst_ipaddr;
    uint8_t     protocol;
    uint8_t     data[0]; // points to l4_tcp_udp_t or icmp_t
} netos_event_ipv4_data_t;

typedef struct __attribute__ ((__packed__)) {
    uint8_t     src_ipaddr[16];
    uint8_t     dst_ipaddr[16];
    uint8_t     protocol;
    uint8_t     data[0]; // points to l4_tcp_udp_t or icmp_t
} netos_event_ipv6_data_t;

typedef struct __attribute__ ((__packed__)) {
    uint8_t     type;
    uint32_t    desc;
    char        ifname[16];
    uint64_t    sec;
    uint64_t    nsec;
    uint16_t    frame_len;
    uint16_t    ethertype;
    uint8_t     data[0]; // points to ipv4_data_t or ipv6_data_t
} netos_event_msg_t;

/**
 * @brief - Defines event header.
 */
typedef struct __attribute__ ((__packed__)) {
    uint32_t magic; // NWOS
    uint8_t version; // 1
} netos_event_hdr_t;

#endif

