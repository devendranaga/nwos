#ifndef STATISTICS_PERFORMANCE_STATISTICS_H
#define STATISTICS_PERFORMANCE_STATISTICS_H

typedef struct {
    std::atomic<std::uint64_t> rx_queue_time_ns;
    std::atomic<std::uint64_t> parse_time_ns;
} perf_statistics_rx_t;

typedef struct {
    perf_statistics_rx_t rx;
} perf_statistics_t;

#endif

