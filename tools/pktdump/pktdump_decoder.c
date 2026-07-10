/**
 * @file   pktdump_decoder.c
 * @brief  Protocol dissector for netos_pktdump.
 *
 * Dissects raw Ethernet frames through the existing netos protocol decoders
 * and formats a single human-readable summary line per packet.
 *
 * Supported protocol stack:
 *   Ethernet
 *     ├── ARP
 *     ├── IPv4
 *     │     ├── TCP
 *     │     ├── UDP
 *     │     ├── ICMPv4
 *     │     └── (other L4 — show proto number)
 *     ├── IPv6
 *     │     └── (next-header shown; full L4 decode omitted for brevity)
 *     └── (other ethertype — shown in hex)
 *
 * All pkt_buffer_t instances are stack-allocated (no heap).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "netos_status.h"
#include "pkt_buffer.h"
#include "ethertypes.h"
#include "protocols.h"
#include "protocol_const.h"
#include "eth.h"
#include "arp_hdr.h"
#include "ipv4_hdr.h"
#include "ipv6_hdr.h"
#include "tcp_hdr.h"
#include "udp_hdr.h"

#include "pktdump_decoder.h"

/* -------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

/** Format a MAC address as "aa:bb:cc:dd:ee:ff". */
static void fmt_mac(const uint8_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/** Format an IPv4 address (host-byte-order) as a dotted-decimal string. */
static void fmt_ipv4(uint32_t addr_hbo, char *buf, size_t len)
{
    struct in_addr in = { .s_addr = htonl(addr_hbo) };
    inet_ntop(AF_INET, &in, buf, (socklen_t)len);
}

/** Format a 16-byte IPv6 address as a colon-hex string. */
static void fmt_ipv6(const uint8_t *addr, char *buf, size_t len)
{
    inet_ntop(AF_INET6, addr, buf, (socklen_t)len);
}

/* -------------------------------------------------------------------------
 * TCP flag string builder — produces "[SYN]", "[ACK]", "[SYN,ACK]", etc.
 * ------------------------------------------------------------------------- */
static void fmt_tcp_flags(const netos_tcp_flags_t *f, char *buf, size_t len)
{
    char tmp[64] = "[";
    bool first = true;

    if (f->syn) { strncat(tmp, first ? "SYN" : ",SYN", sizeof(tmp)-strlen(tmp)-1); first = false; }
    if (f->ack) { strncat(tmp, first ? "ACK" : ",ACK", sizeof(tmp)-strlen(tmp)-1); first = false; }
    if (f->fin) { strncat(tmp, first ? "FIN" : ",FIN", sizeof(tmp)-strlen(tmp)-1); first = false; }
    if (f->rst) { strncat(tmp, first ? "RST" : ",RST", sizeof(tmp)-strlen(tmp)-1); first = false; }
    if (f->psh) { strncat(tmp, first ? "PSH" : ",PSH", sizeof(tmp)-strlen(tmp)-1); first = false; }
    if (f->urg) { strncat(tmp, first ? "URG" : ",URG", sizeof(tmp)-strlen(tmp)-1); first = false; }
    if (first)  { strncat(tmp, ".",                    sizeof(tmp)-strlen(tmp)-1); }

    strncat(tmp, "]", sizeof(tmp) - strlen(tmp) - 1);
    snprintf(buf, len, "%s", tmp);
}

/* -------------------------------------------------------------------------
 * L4 decoders — called after IPv4 header is parsed
 * ------------------------------------------------------------------------- */

static pktdump_proto_t decode_tcp(pkt_buffer_t *pb,
                                  const char *src_ip, const char *dst_ip,
                                  char *out, size_t out_len)
{
    netos_tcp_hdr_t tcp;
    memset(&tcp, 0, sizeof(tcp));

    if (netos_tcp_decode(&tcp, pb) != NETOS_STATUS_SUCCESS) {
        snprintf(out, out_len, "IP   %s > %s   TCP [decode error]",
                 src_ip, dst_ip);
        return PKTDUMP_PROTO_IPV4_TCP;
    }

    char flags[64];
    fmt_tcp_flags(&tcp.flags, flags, sizeof(flags));

    snprintf(out, out_len,
             "IP   %s:%u > %s:%u   TCP %s seq=%u ack=%u win=%u",
             src_ip, tcp.src_port, dst_ip, tcp.dst_port,
             flags, tcp.seq_no, tcp.ack_no, tcp.window);

    return PKTDUMP_PROTO_IPV4_TCP;
}

static pktdump_proto_t decode_udp(pkt_buffer_t *pb,
                                  const char *src_ip, const char *dst_ip,
                                  char *out, size_t out_len)
{
    netos_udp_hdr_t udp;
    memset(&udp, 0, sizeof(udp));

    if (netos_udp_decode(&udp, pb) != NETOS_STATUS_SUCCESS) {
        snprintf(out, out_len, "IP   %s > %s   UDP [decode error]",
                 src_ip, dst_ip);
        return PKTDUMP_PROTO_IPV4_UDP;
    }

    snprintf(out, out_len,
             "IP   %s:%u > %s:%u   UDP len=%u",
             src_ip, udp.src_port, dst_ip, udp.dst_port, udp.length);

    return PKTDUMP_PROTO_IPV4_UDP;
}

static pktdump_proto_t decode_icmp(pkt_buffer_t *pb,
                                   const char *src_ip, const char *dst_ip,
                                   char *out, size_t out_len)
{
    /* Read ICMP type and code (first two bytes). */
    if (pkt_buffer_has_short_rx_len(pb, 2)) {
        snprintf(out, out_len, "IP   %s > %s   ICMP [truncated]",
                 src_ip, dst_ip);
        return PKTDUMP_PROTO_IPV4_ICMP;
    }

    uint8_t type, code;
    pkt_buffer_decode_byte(pb, &type);
    pkt_buffer_decode_byte(pb, &code);

    const char *type_str;
    switch (type) {
        case 0:  type_str = "Echo Reply";        break;
        case 3:  type_str = "Dest Unreachable";  break;
        case 8:  type_str = "Echo Request";      break;
        case 11: type_str = "Time Exceeded";     break;
        default: type_str = "Unknown";           break;
    }

    snprintf(out, out_len,
             "IP   %s > %s   ICMP %s (type=%u code=%u)",
             src_ip, dst_ip, type_str, type, code);

    return PKTDUMP_PROTO_IPV4_ICMP;
}

/* -------------------------------------------------------------------------
 * Top-level frame decoders
 * ------------------------------------------------------------------------- */

static pktdump_proto_t decode_arp(pkt_buffer_t *pb,
                                  char *out, size_t out_len)
{
    netos_arp_hdr_t arp;
    memset(&arp, 0, sizeof(arp));

    if (netos_arp_decode(&arp, pb) != NETOS_STATUS_SUCCESS) {
        snprintf(out, out_len, "ARP  [decode error]");
        return PKTDUMP_PROTO_ARP;
    }

    char spa[INET_ADDRSTRLEN], tpa[INET_ADDRSTRLEN];
    fmt_ipv4(arp.sender_protocol_addr, spa, sizeof(spa));
    fmt_ipv4(arp.target_protocol_addr, tpa, sizeof(tpa));

    if (arp.op == NETOS_ARP_OP_REQUEST) {
        snprintf(out, out_len, "ARP  Who has %s? Tell %s", tpa, spa);
    } else if (arp.op == NETOS_ARP_OP_REPLY) {
        char sha[24];
        fmt_mac(arp.sender_hwaddr, sha, sizeof(sha));
        snprintf(out, out_len, "ARP  Reply: %s is at %s", spa, sha);
    } else {
        snprintf(out, out_len, "ARP  op=%u", arp.op);
    }

    return PKTDUMP_PROTO_ARP;
}

static pktdump_proto_t decode_ipv4(pkt_buffer_t *pb,
                                   char *out, size_t out_len)
{
    netos_ipv4_hdr_t ipv4;
    memset(&ipv4, 0, sizeof(ipv4));

    if (netos_ipv4_decode(&ipv4, pb) != NETOS_STATUS_SUCCESS) {
        snprintf(out, out_len, "IPv4 [decode error]");
        return PKTDUMP_PROTO_IPV4_TCP; /* best guess for counter */
    }

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    fmt_ipv4(ipv4.src_ipaddr, src, sizeof(src));
    fmt_ipv4(ipv4.dst_ipaddr, dst, sizeof(dst));

    switch ((netos_protocol_t)ipv4.protocol) {
        case NETOS_PROTOCOL_TCP:
            return decode_tcp(pb, src, dst, out, out_len);
        case NETOS_PROTOCOL_UDP:
            return decode_udp(pb, src, dst, out, out_len);
        case NETOS_PROTOCOL_ICMP:
            return decode_icmp(pb, src, dst, out, out_len);
        default:
            snprintf(out, out_len,
                     "IP   %s > %s   proto=%u len=%u",
                     src, dst, ipv4.protocol, ipv4.total_len);
            return PKTDUMP_PROTO_OTHER;
    }
}

static pktdump_proto_t decode_ipv6(pkt_buffer_t *pb,
                                   char *out, size_t out_len)
{
    netos_ipv6_hdr_t ipv6;
    memset(&ipv6, 0, sizeof(ipv6));

    if (netos_ipv6_decode(&ipv6, pb) != NETOS_STATUS_SUCCESS) {
        snprintf(out, out_len, "IP6  [decode error]");
        return PKTDUMP_PROTO_IPV6;
    }

    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    fmt_ipv6(ipv6.src_ipaddr, src, sizeof(src));
    fmt_ipv6(ipv6.dst_ipaddr, dst, sizeof(dst));

    snprintf(out, out_len,
             "IP6  %s > %s   nh=%u len=%u",
             src, dst, ipv6.nh, ipv6.payload_len);

    return PKTDUMP_PROTO_IPV6;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

pktdump_proto_t netos_pktdump_decode(const uint8_t *data, int len,
                                     char *out, size_t out_len)
{
    /* Set up a stack-allocated packet buffer — no heap needed. */
    pkt_buffer_t pb;
    memset(&pb, 0, sizeof(pb));

    /* Guard: clamp to our internal buffer capacity. */
    uint32_t copy_len = ((uint32_t)len > NETOS_PKT_BUFFER_LEN)
                        ? NETOS_PKT_BUFFER_LEN
                        : (uint32_t)len;

    memcpy(pb.buffer, data, copy_len);
    pb.rx_len = copy_len;
    pb.offset = 0;

    /* --- Ethernet layer --- */
    netos_eth_hdr_t eth;
    memset(&eth, 0, sizeof(eth));

    if (netos_eth_decode(&eth, &pb) != NETOS_STATUS_SUCCESS) {
        snprintf(out, out_len, "ETH  [decode error] len=%d", len);
        return PKTDUMP_PROTO_OTHER;
    }

    /* Dispatch on ethertype. */
    switch ((netos_ethertype_t)eth.ethertype) {
        case NETOS_ETHERTYPE_ARP:
            return decode_arp(&pb, out, out_len);

        case NETOS_ETHERTYPE_IPV4:
            return decode_ipv4(&pb, out, out_len);

        case NETOS_ETHERTYPE_IPV6:
            return decode_ipv6(&pb, out, out_len);

        default: {
            char src_mac[24], dst_mac[24];
            fmt_mac(eth.src, src_mac, sizeof(src_mac));
            fmt_mac(eth.dst, dst_mac, sizeof(dst_mac));
            snprintf(out, out_len,
                     "ETH  %s > %s   ethertype=0x%04x len=%d",
                     src_mac, dst_mac, eth.ethertype, len);
            return PKTDUMP_PROTO_OTHER;
        }
    }
}
