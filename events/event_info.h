#ifndef NETOS_EVENT_INFO_H
#define NETOS_EVENT_INFO_H

/**
 * @brief - Defines Event Type.
 */
typedef enum {
    NETOS_EVENT_TYPE_ALLOW,
    NETOS_EVENT_TYPE_DENY,
    NETOS_EVENT_TYPE_INVAL,
} netos_event_type_t;

/**
 * @brief - Defines Event Description.
 */
typedef enum {
    // Ethernet related events
    NETOS_EVENT_DESC_ETH_SHORT_HDR                      = 0x00000001,

    // ARP related events
    NETOS_EVENT_DESC_ARP_SHORT_HDR                      = 0x00001000,
    NETOS_EVENT_DESC_ARP_INVAL_SENDER_HWADDR,
    NETOS_EVENT_DESC_ARP_INVAL_SENDER_PROTOCOL_ADDR,

    // IPv4 related events
    NETOS_EVENT_DESC_IPV4_SHORT_HDR_LEN                 = 0x00002000,
    NETOS_EVENT_DESC_IPV4_INVAL_VERSION,
    NETOS_EVENT_DESC_IPV4_INVAL_HDR_LEN,
    NETOS_EVENT_DESC_IPV4_TOTAL_LEN_ZERO,
    NETOS_EVENT_DESC_IPV4_RESERVED_BIT_SET,
    NETOS_EVENT_DESC_IPV4_DF_MF_SET,
    NETOS_EVENT_DESC_IPV4_TTL_ZERO,
    NETOS_EVENT_DESC_IPV4_CHECKSUM_FAILED,
    NETOS_EVENT_DESC_IPV4_SRC_DST_IP_SAME,

    // ICMP related events
    NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REQ                = 0x00003000,
    NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REPLY,
    NETOS_EVENT_DESC_ICMP_SHORT_TS_REQ,
    NETOS_EVENT_DESC_ICMP_SHORT_TS_REPLY,
    NETOS_EVENT_DESC_ICMP_TS_REQ_CONTAINS_DATA,
    NETOS_EVENT_DESC_ICMP_TS_REPLY_CONTAINS_DATA,
    NETOS_EVENT_DESC_ICMP_CHECKSUM_VERIFY_FAILED,

    // TCP related events
    NETOS_EVENT_DESC_TCP_CHECKSUM_VERIFY_FAILED         = 0x00004000,
    NETOS_EVENT_DESC_TCP_SHORT_HDR_LEN                  = 0x00004001,

    // UDP related events
    NETOS_EVENT_DESC_UDP_CHECKSUM_VERIFY_FAILED         = 0x00005000,

    // ICMP6 related events
    NETOS_EVENT_DESC_ICMP6_CHECKSUM_VERIFY_FAILED       = 0x00006000,

    // invalid event description id
    NETOS_EVENT_DESC_INVAL                              = 0xFAFAFAFA,
} netos_event_desc_t;

typedef struct __attribute__ ((__packed__)) {
    uint32_t version;
    uint32_t magic;
} netos_event_hdr_t;

/**
 * @brief - Defines event info.
 */
typedef struct netos_event_info {
    struct __attribute__ ((__packed__)) {
        netos_event_type_t      type;
        netos_event_desc_t      desc;
        char                    ifname[15];
        uint64_t                sec;
        uint64_t                nsec;
        uint32_t                frame_len;
        union {
            struct {
                uint32_t        src_addr;
                uint32_t        dst_addr;
            } v4;
            struct {
                uint8_t         src_addr[16];
                uint8_t         dst_addr[16];
            } v6;
        } ip;
        uint8_t                 protocol;
        union {
            struct {
                uint16_t        src_port;
                uint16_t        dst_port;
            } ports;
            struct {
                uint8_t         type;
                uint8_t         code;
            } icmp;
        } l4;
    } s;

    struct netos_event_info *next;
} netos_event_info_t;

/**
 * @brief - Initializes the event type and description.
 */
#define NETOS_EVENT_INIT(__evt_type, __evt_desc) do {\
    __evt_type = NETOS_EVENT_TYPE_INVAL;\
    __evt_desc = NETOS_EVENT_DESC_INVAL;\
} while (0)

/**
 * @brief - Initialize the event info structure.
 *
 * @param [in] __evt_info - initialize the event info structure.
 */
#define NETOS_EVENT_INFO_INIT(__evt_info) do {\
    (__evt_info)->s.type        = NETOS_EVENT_TYPE_INVAL;\
    (__evt_info)->s.desc        = NETOS_EVENT_DESC_INVAL;\
    memset((__evt_info)->s.ifname, 0, sizeof((__evt_info)->ifname));\
    (__evt_info)->s.sec         = 0;\
    (__evt_info)->s.nsec        = 0;\
    (__evt_info)->s.frame_len   = 0;\
} while (0)

/**
 * @brief - Copy source string into destination.
 *
 * @param [in] __dst - destination string.
 * @param [in] __src - source string.
 */
#define NETOS_STRING_COPY(__dst, __src) do {\
    uint32_t __i = 0;\
    while ((__src) && (*(__src) != '\0')) {\
        (__dst)[__i] = *(__src);\
        __i ++;\
        __src ++;\
    }\
} while (0)

/**
 * @brief - Create an Event info structure.
 *
 * @param [out] __evt_info - Event Info.
 * @param [in] __ifname - interface name.
 * @param [in] __sec - timestamp seconds.
 * @param [in] __nsec - timestamp nanoseconds.
 * @param [in] __evt_type - event type.
 * @param [in] __evt_desc - event description.
 * @param [in] __frame_len - frame length.
 */
#define NETOS_EVENT_INFO_CREATE(__evt_info, __ifname,\
                                __sec, __nsec,\
                                __evt_type, __evt_desc,\
                                __frame_len) do {\
    (__evt_info)->s.type        = __evt_type;\
    (__evt_info)->s.desc        = __evt_desc;\
    (__evt_info)->s.sec         = __sec;\
    (__evt_info)->s.nsec        = __nsec;\
    NETOS_STRING_COPY((__evt_info)->s.ifname, __ifname);\
    (__evt_info)->s.frame_len   = __frame_len;\
} while (0)

/**
 * @brief - Add an event.
 */
#define NETOS_EVENT_INFO_ADD_EVENT(__evt_head, __evt_tail, __evt_info) do {\
    if (!__evt_head) {\
        __evt_head = __evt_info;\
        __evt_tail = __evt_info;\
    } else {\
        (__evt_tail)->next = __evt_info;\
        (__evt_tail) = __evt_info;\
    }\
} while (0)

/**
 * @brief - Delete an event from head. Move the head to next element.
 */
#define NETOS_EVENT_INFO_DEL_EVENT_HEAD(__evt_head) do {\
    struct netos_event_info *item;\
    item = (__evt_head);\
    if (__evt_head) {\
        (__evt_head) = (__evt_head)->next;\
        free(item);\
    }\
} while (0)

#endif

