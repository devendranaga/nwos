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
    uint32_t    rule_id;
    uint8_t     type;
    uint32_t    desc;
    char        ifname[16];
    uint64_t    sec;
    uint64_t    nsec;
    uint16_t    frame_len;
    uint16_t    ethertype;
    uint8_t     data[0]; // points to ipv4_data_t or ipv6_data_t
} netos_event_msg_t;

#define NETOS_EVENT_HDR_SIGNED            0x00000001
#define NETOS_EVENT_HDR_ENCRYPTED         0x00000002

#define NETOS_EVENT_SIG_ALG_AES_GMAC      0x01
#define NETOS_EVENT_SIG_ALG_AES_CMAC      0x02

#define NETOS_EVENT_ENC_ALG_AES_GCM       0x01

/**
 * @brief - Defines event header.
 */
typedef struct __attribute__ ((__packed__)) {
    uint32_t magic; // NWOS
    uint8_t  version; // 1
    //
    // HDR_SIGNED meaning the entire data content after this header is signed.
    // HDR_ENCRYPTED meaning the entire data content after this header is encrypted.
    //     for AES-GCM
    //     1. the header serves as AAD
    //     2. the IV is the 4 byte ts_sec | 4 byte ts_usec | 4 byte 0s
    //     3. the data as plaintext
    // TODO: Probably need to think if 4 byte 0s can be replaced with something else for strong IV.
    //
    // user can simply set flags to 0 and do not encrypt any file contents.
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    uint32_t flags;
    uint8_t  signature_alg;
    uint8_t  enc_alg;
    uint8_t  signature_len; // for cmac and gmac its the MAC or the TAG
    uint8_t  signature[0]; // its 16 bytes for CMAC and GMAC
} netos_event_hdr_t;

#endif

