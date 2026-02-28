#ifndef STATISTICS_PERFORMANCE_STATISTICS_H
#define STATISTICS_PERFORMANCE_STATISTICS_H

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct __attribute__ ((__packed__)) {
    uint64_t rx_queue_time_ns;
    uint64_t parse_time_ns;
} perf_statistics_rx_t;

typedef struct __attribute__ ((__packed__)) {
    perf_statistics_rx_t rx;
} perf_statistics_t;

#if defined(__cplusplus)
}
#endif

#endif

