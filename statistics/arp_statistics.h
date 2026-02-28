#ifndef STATISTICS_ARP_STATISTICS_H
#define STATISTICS_ARP_STATISTICS_H

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct __attribute__ ((__packed__)) {
    uint64_t arp_reply_time_ns;
    uint64_t arp_processing_time_ns;
} arp_statistics_rx_t;

typedef struct __attribute__ ((__packed__)) {
    arp_statistics_rx_t rx;
} arp_statistics_t;

#if defined(__cplusplus)
}
#endif

#endif

