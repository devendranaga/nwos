#ifndef STATISTICS_ERGESS_STATISTICS_H
#define STATISTICS_ERGESS_STATISTICS_H

typedef struct {
    std::atomic<std::uint64_t> egress_drop_buffer_full;
} egress_statistics_t;

#endif

