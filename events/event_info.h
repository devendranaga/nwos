#ifndef NETOS_EVENT_INFO_H
#define NETOS_EVENT_INFO_H

typedef enum {
    NETOS_EVENT_TYPE_ALLOW,
    NETOS_EVENT_TYPE_DENY,
    NETOS_EVENT_TYPE_INVAL,
} netos_event_type_t;

typedef enum {
    NETOS_EVENT_DESC_ETH_SHORT_HDR = 1,
    NETOS_EVENT_DESC_ARP_SHORT_HDR,
    NETOS_EVENT_DESC_ARP_INVAL_SENDER_HWADDR,
    NETOS_EVENT_DESC_INVAL = 0xFAFAFAFA,
} netos_event_desc_t;

typedef struct netos_event_info {
    netos_event_type_t      type;
    netos_event_desc_t      desc;
    char                    ifname[15];
    uint64_t                sec;
    uint64_t                nsec;
    uint32_t                frame_len;

    struct netos_event_info *next;
} netos_event_info_t;

#define NETOS_EVENT_INIT(__evt_type, __evt_desc) do {\
    __evt_type = NETOS_EVENT_TYPE_INVAL;\
    __evt_desc = NETOS_EVENT_DESC_INVAL;\
} while (0)

#define NETOS_EVENT_INFO_INIT(__evt_info) do {\
    (__evt_info)->type = NETOS_EVENT_TYPE_INVAL;\
    (__evt_info)->desc = NETOS_EVENT_DESC_INVAL;\
    memset((__evt_info)->ifname, 0, sizeof((__evt_info)->ifname));\
    (__evt_info)->sec = 0;\
    (__evt_info)->nsec = 0;\
    (__evt_info)->frame_len = 0;\
} while (0)

#define NETOS_EVENT_INFO_CREATE(__evt_info, __ifname, __sec, __nsec, __evt_type, __evt_desc, __frame_len) do {\
    (__evt_info)->type = __evt_type;\
    (__evt_info)->desc = __evt_desc;\
    (__evt_info)->sec = __sec;\
    (__evt_info)->nsec = __nsec;\
    memcpy((__evt_info)->ifname, ifname, sizeof((__evt_info)->ifname));\
    (__evt_info)->frame_len = __frame_len;\
} while (0)

#define NETOS_EVENT_INFO_ADD_EVENT(__evt_head, __evt_tail, __evt_info) do {\
    if (!__evt_head) {\
        __evt_head = __evt_info;\
        __evt_tail = __evt_info;\
    } else {\
        (__evt_tail)->next = __evt_info;\
        (__evt_tail) = __evt_info;\
    }\
} while (0)

#define NETOS_EVENT_INFO_DEL_EVENT_HEAD(__evt_head) do {\
    struct netos_event_info *item;\
    item = (__evt_head);\
    (__evt_head) = (__evt_head)->next;\
    free(item);\
} while (0)

#endif

