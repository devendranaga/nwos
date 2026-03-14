#ifndef STATISTICS_ARP_STATISTICS_H
#define STATISTICS_ARP_STATISTICS_H

typedef struct {
    std::atomic<std::uint64_t> arp_reply_time_ns;
    std::atomic<std::uint64_t> arp_processing_time_ns;
} arp_statistics_rx_t;

typedef struct {
    arp_statistics_rx_t rx;
} arp_statistics_t;

#endif

