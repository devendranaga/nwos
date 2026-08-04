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
#include "macsec_hdr.h"
#include "pcap_intf.h"
#include "raw_socket.h"
#include "crypto_ctx.h"

/**
 * @brief - Defines pgen context.
 */
struct pgen {
    netos_eth_hdr_t             eth_hdr;
    netos_vlan_hdr_t            vlan_hdr;
    netos_arp_hdr_t             arp_hdr;
    netos_ipv4_hdr_t            ipv4_hdr;
    netos_icmp_hdr_t            icmp_hdr;
    netos_macsec_hdr_t          macsec_hdr;
    netos_udp_hdr_t             udp_hdr;
    bool                        eth_enable;
    bool                        vlan_enable;
    bool                        arp_enable;
    bool                        ipv4_enable;
    bool                        icmp_enable;
    bool                        macsec_enable;
    bool                        udp_enable;
    uint64_t                    ipg_ns;
    uint32_t                    n_frames;
    char                        *ifname;
    uint32_t                    len;
    netos_pcap_context_t        *pcap_ctx;
    netos_raw_socket_ctx_t      *raw;
    netos_crypto_ctx_t          *crypto_ctx;
    void                        *gcm_ctx;
};

struct pgen_token {
    char name[1024];
};

#endif

