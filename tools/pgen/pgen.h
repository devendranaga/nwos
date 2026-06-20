#ifndef NETOS_PGEN_H
#define NETOS_PGEN_H

#include "eth.h"
#include "arp.h"
#include "raw_socket.h"

struct pgen {
    netos_eth_hdr_t     eth_hdr;
    netos_arp_hdr_t     arp_hdr;
    bool                eth_enable;
    bool                arp_enable;
    uint64_t            ipg_ns;
    uint32_t            n_frames;
    char                *ifname;
    uint32_t            len;
    raw_socket_ctx_t    *raw;
};

#endif

