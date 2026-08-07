#ifndef NETOS_PACKET_PARSER_H
#define NETOS_PACKET_PARSER_H

#include "raw_socket.h"
#include "eth.h"
#include "arp_hdr.h"
#include "vlan.h"
#include "macsec_hdr.h"
#include "ipv4_hdr.h"
#include "ipv6_hdr.h"
#include "udp_hdr.h"
#include "tcp_hdr.h"
#include "icmp_hdr.h"
#include "icmp6_hdr.h"
#include "protocols.h"

#define NETOS_MAX_VLAN_TUNNELS 12

typedef struct netos_packet_parser {
    char                    *ifname;
    void                    *this_thread;
    netos_raw_socket_ctx_t  *raw;
    netos_eth_hdr_t         eh;
    netos_arp_hdr_t         arp_hdr;
    uint16_t                ethertype;
    netos_vlan_hdr_t        vlan_hdr[NETOS_MAX_VLAN_TUNNELS];
    uint32_t                n_vlans;
    netos_macsec_hdr_t      macsec_hdr;
    bool                    has_l2_protocol;

#define NETOS_IS_IPV4_FRAME(__pkt_parser) ((__pkt_parser)->ethertype == NETOS_ETHERTYPE_IPV4)
#define NETOS_IS_IPV6_FRAME(__pkt_parser) ((__pkt_parser)->ethertype == NETOS_ETHERTYPE_IPV6)
#define NETOS_IS_TCP_PROTOCOL(__pkt_parser) ((__pkt_parser)->protocol == NETOS_PROTOCOL_TCP)
#define NETOS_IS_UDP_PROTOCOL(__pkt_parser) ((__pkt_parser)->protocol == NETOS_PROTOCOL_UDP)
    union {
        netos_ipv4_hdr_t    ipv4_hdr;
        netos_ipv6_hdr_t    ipv6_hdr;
    } l3;

    uint8_t                 protocol;

    union {
        netos_tcp_hdr_t     tcp_hdr;
        netos_udp_hdr_t     udp_hdr;
        netos_icmp_hdr_t    icmp_hdr;
        netos_icmp6_hdr_t   icmp6_hdr;
    } l4;
} netos_packet_parser_t;

netos_status_t netos_parse_frame(pkt_buffer_t *pkt_buf,
                                 netos_packet_parser_t *parsed_data);

#endif
