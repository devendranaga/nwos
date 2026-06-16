#ifndef NETOS_RAW_SOCKET_H
#define NETOS_RAW_SOCKET_H

#include "protocol_const.h"
#include "netos_status.h"

/**
 * @brief - Defines Raw socket context.
 */
typedef struct raw_socket_ctx {
    int         fd;
    char        *ifname;
    uint8_t     mac[NETOS_MACADDR_LEN];
    uint32_t    ipaddr;
    int         ifindex;
} raw_socket_ctx_t;

/**
 * @brief - initializes raw socket.
 *
 * @param [in] ifname - interface name.
 *
 * @return raw socket context on sucess and NULL pointer on failure.
 */
raw_socket_ctx_t *netos_raw_socket_init(const char *ifname);

int netos_raw_socket_rx(raw_socket_ctx_t *raw, uint8_t *data, uint32_t data_len);

int netos_raw_socket_tx(raw_socket_ctx_t *raw, uint8_t *data, uint32_t data_len);

#endif

