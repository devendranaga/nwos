#ifndef PLATFORM_LINUX_PERF_LINUX_H
#define PLATFORM_LINUX_PERF_LINUX_H

#include <sys/time.h>
#include <string>
#include <vector>

struct perf_data {
    struct timespec start_ns;
    struct timespec end_ns;
};

class perf_event {
    public:
        explicit perf_event(const std::string &name) : name_(name) { }
        ~perf_event() { }

        void capture_start();
        void capture_end();
        double average();
        double sum();

    private:
        std::string name_;
        std::vector<perf_data> perf_data_;
};

class perf_linux {
    public:
        static perf_linux *instance() {
            static perf_linux p;
            return &p;
        }
        ~perf_linux() { }

    private:
        explicit perf_linux() { }
        std::vector<perf_event> events_;
};

#endif
