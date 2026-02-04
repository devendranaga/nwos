#ifndef NETOS_CLOUD_INTERFACE_H
#define NETOS_CLOUD_INTERFACE_H

#include <stdint.h>

#include "stats_interface.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define CLOUD_INTF_VERSION 1

enum cloud_interface_type {
    CLOUD_INTF_TX_STATS = 1,
    CLOUD_INTF_RX_STATS,
};

struct cloud_interface_msg {
    uint8_t                 version;
    cloud_interface_type    type;
    /**
     * 1. Points to stats_intf_tx if type == CLOUD_INTF_TX_STATS
     * 2. Points to stats_intf_rx if type == CLOUD_INTF_RX_STATS
     */
    uint8_t                 data[0];
} __attribute__ ((__packed__));

#if defined(__cplusplus)
}
#endif

#endif
