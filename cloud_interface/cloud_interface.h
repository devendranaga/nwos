#ifndef NETOS_CLOUD_INTERFACE_H
#define NETOS_CLOUD_INTERFACE_H

#include <stdint.h>

#include "stats_interface.h"

#define CLOUD_INTF_VERSION 1

enum cloud_interface_type {
    CLOUD_INTF_TX_STATS = 1,
    CLOUD_INTF_RX_STATS,
};

typedef struct __attribute__ ((__packed__)) {
    uint8_t                 version;
    cloud_interface_type    type;
    /**
     * 1. Points to stats_intf_tx if type == CLOUD_INTF_TX_STATS
     * 2. Points to stats_intf_rx if type == CLOUD_INTF_RX_STATS
     */
    uint8_t                 data[0];
} cloud_interface_msg_t;

#define CLOUD_INTERFACE_MSG_INIT(__buf, __intf_ptr) {\
    __intf_ptr = (cloud_interface_msg_t *)__buf;\
    __intf_ptr->version = CLOUD_INTF_VERSION;\
}

#define CLOUD_INTERFACE_MSG_SET_TX_STATS(__buf, __intf_ptr) {\
    CLOUD_INTERFACE_MSG_INIT(__buf, __intf_ptr);\
    __intf_ptr->type = CLOUD_INTF_TX_STATS;\
}

#define CLOUD_INTERFACE_MSG_SET_RX_STATS(__buf, __intf_ptr) {\
    CLOUD_INTERFACE_MSG_INIT(__buf, __intf_ptr);\
    __intf_ptr->type = CLOUD_INTF_RX_STATS;\
}

inline uint32_t cloud_interface_msg_get_stats_tx_len(cloud_interface_msg_t *msg)
{
    return sizeof(cloud_interface_msg_t) +
           stats_interface_get_tx_msg_len();
}

#endif
