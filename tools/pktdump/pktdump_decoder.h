#ifndef NETOS_PKTDUMP_DECODER_H
#define NETOS_PKTDUMP_DECODER_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Protocol classification returned by the decoder.
 *
 * Used by the RX loop to update the correct per-protocol counter
 * in netos_pktdump_stats_t without re-examining the packet.
 */
typedef enum {
    PKTDUMP_PROTO_ARP       = 0,
    PKTDUMP_PROTO_IPV4_TCP  = 1,
    PKTDUMP_PROTO_IPV4_UDP  = 2,
    PKTDUMP_PROTO_IPV4_ICMP = 3,
    PKTDUMP_PROTO_IPV6      = 4,
    PKTDUMP_PROTO_OTHER     = 5,
} pktdump_proto_t;

/**
 * @brief Decode raw frame bytes into a human-readable one-line summary.
 *
 * Layers dissected: Ethernet → ARP / IPv4 (TCP / UDP / ICMP) / IPv6.
 * Uses a stack-allocated pkt_buffer_t — no heap allocation.
 *
 * Example outputs:
 *   "ARP  Who has 192.168.1.1? Tell 192.168.1.5"
 *   "IP   192.168.1.5:54321 > 10.0.0.1:80   [SYN] seq=1234 win=65535 len=60"
 *   "IP   192.168.1.5 > 10.0.0.1   ICMP Echo Request id=1 seq=42"
 *   "IP   10.0.0.1:53 > 192.168.1.5:5000   UDP len=72"
 *   "IP6  fe80::1 > ff02::1   proto=58 len=24"
 *   "ETH  aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff   ethertype=0x88b5 len=64"
 *
 * @param data    Pointer to the raw frame bytes (from recvfrom).
 * @param len     Number of valid bytes in data.
 * @param out     Output buffer for the formatted string.
 * @param out_len Size of the output buffer.
 * @return        Protocol classification (for stats counter selection).
 */
pktdump_proto_t netos_pktdump_decode(const uint8_t *data, int len,
                                     char *out, size_t out_len);

#endif /* NETOS_PKTDUMP_DECODER_H */
