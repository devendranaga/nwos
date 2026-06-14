#ifndef NETOS_PGEN_H
#define NETOS_PGEN_H

#include "eth.h"
#include "raw_socket.h"

struct pgen {
    netos_eth_hdr_t     eth_hdr;
    uint64_t            ipg_ns;
    uint32_t            n_frames;
    char                *ifname;
    uint32_t            len;
    raw_socket_ctx_t    *raw;
};

#endif

