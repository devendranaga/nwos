#ifndef NETOS_PROTOCOLS_TCP_H
#define NETOS_PROTOCOLS_TCP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
} netos_tcp_hdr_t;

#if defined(__cplusplus)
}
#endif

#endif
