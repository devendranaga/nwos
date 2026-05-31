#ifndef NETOS_PACKET_PARSER_H
#define NETOS_PACKET_PARSER_H

#include "raw_socket.h"
#include "eth.h"
#include "arp.h"
#include "vlan.h"
#include "macsec.h"
#include "ipv4.h"
#include "udp.h"

#define NETOS_MAX_VLAN_TUNNELS 12

typedef struct netos_packet_parser {
    char                    *ifname;
    raw_socket_ctx_t        *raw;
    netos_eth_hdr_t         eh;
    uint16_t                ethertype;
    netos_vlan_hdr_t        vlan_hdr[NETOS_MAX_VLAN_TUNNELS];
    uint32_t                n_vlans;
    netos_macsec_hdr_t      macsec_hdr;
    bool                    has_l2_protocol;

    union {
        netos_arp_hdr_t     arp_hdr;
    } l2;

    union {
        netos_ipv4_hdr_t    ipv4_hdr;
    } l3;

    uint8_t                 protocol;

    union {
        netos_udp_hdr_t     udp_hdr;
    } l4;
} netos_packet_parser_t;

#define HAS_IPV4

netos_status_t netos_parse_frame(pkt_buffer_t *pkt_buf,
                                 netos_packet_parser_t *parsed_data);

#endif
