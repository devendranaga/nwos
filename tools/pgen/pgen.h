#ifndef NETOS_PGEN_H
#define NETOS_PGEN_H

#include "eth.h"
#include "common.h"
#include "vlan.h"
#include "arp_hdr.h"
#include "ipv4_hdr.h"
#include "tcp_hdr.h"
#include "udp_hdr.h"
#include "icmp_hdr.h"
#include "raw_socket.h"

/**
 * @brief - Defines pgen context.
 */
struct pgen {
    netos_eth_hdr_t             eth_hdr;
    netos_vlan_hdr_t            vlan_hdr;
    netos_arp_hdr_t             arp_hdr;
    netos_ipv4_hdr_t            ipv4_hdr;
    netos_icmp_hdr_t            icmp_hdr;
    bool                        eth_enable;
    bool                        vlan_enable;
    bool                        arp_enable;
    bool                        ipv4_enable;
    bool                        icmp_enable;
    uint64_t                    ipg_ns;
    uint32_t                    n_frames;
    char                        *ifname;
    uint32_t                    len;
    netos_raw_socket_ctx_t      *raw;
};

#endif

