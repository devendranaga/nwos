#ifndef NETOS_PERF_INTF_H
#define NETOS_PERF_INTF_H

#include <string.h>
#include <time.h>
#include <sys/time.h>

#if defined(NETOS_PERF)

/**
 * @brief - Timestamps are in nanoseconds but i suppose
 * we cannot really capture them at nanosecond level
 * because of syscall execution and return back.
 *
 * We should look for a better approach.
 */
typedef struct {
    struct timespec start_ns;
    struct timespec end_ns;
    double          elapsed_ns;
#define perf_delta(__perf_evt) (__perf_evt).elapsed_ns
#define perf_delta_us(__perf_evt) ((__perf_evt).elapsed_ns / 1000.0)
} netos_perf_event_t;

/**
 * @brief - Initializes the perf event structure.
 */
#define NETOS_PERF_EVENT_INITIALIZE(__perf_evt) do {            \
    memset(&(__perf_evt).start_ns, 0, sizeof(struct timespec)); \
    memset(&(__perf_evt).end_ns, 0, sizeof(struct timespec));   \
    (__perf_evt).elapsed_ns = 0;                                \
} while (0)

/**
 * @brief - Start the perf measurement.
 */
#define NETOS_PERF_EVENT_START(__perf_evt) do {             \
    clock_gettime(CLOCK_MONOTONIC, &(__perf_evt).start_ns); \
} while (0)

/**
 * @brief - Get the delta measurement report.
 */
#define NETOS_PERF_EVENT_DELTA(__perf_evt) do {                                                 \
    (__perf_evt).elapsed_ns = \
                ((((__perf_evt).end_ns.tv_sec - (__perf_evt).start_ns.tv_sec) * 1000000000L) +\
                 ((__perf_evt).end_ns.tv_nsec - (__perf_evt).start_ns.tv_nsec)); \
} while (0)

/**
 * @brief - End the perf measurement.
 */
#define NETOS_PERF_EVENT_END(__perf_evt) do {               \
    clock_gettime(CLOCK_MONOTONIC, &(__perf_evt).end_ns);   \
    NETOS_PERF_EVENT_DELTA(__perf_evt);                     \
} while (0)

#else

typedef uint32_t netos_perf_event_t;

#define NETOS_PERF_EVENT_INITIALIZE(__perf_evt)     do { } while (0)
#define NETOS_PERF_EVENT_START(__perf_evt)          do { } while (0)
#define NETOS_PERF_EVENT_DELTA(__perf_evt)          do { } while (0)
#define NETOS_PERF_EVENT_END(__perf_evt)            do { } while (0)

#endif

#endif

