#ifndef NETOS_RAW_SOCKET_H
#define NETOS_RAW_SOCKET_H

#include "netos_status.h"

typedef struct raw_socket_ctx {
    int fd;
    char *ifname;
} raw_socket_ctx_t;

raw_socket_ctx_t *netos_raw_socket_init(const char *ifname);

int netos_raw_socket_rx(raw_socket_ctx_t *raw, uint8_t *data, uint32_t data_len);

#endif

