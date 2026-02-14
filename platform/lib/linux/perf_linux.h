#ifndef PLATFORM_LINUX_PERF_LINUX_H
#define PLATFORM_LINUX_PERF_LINUX_H

#include <string>
#include <vector>
#include <memory>
#include <sys/time.h>
#include <time.h>

namespace netos {

namespace lib {

class perf_event {
    public:
        explicit perf_event(const std::string &name) : name_(name) { }
        ~perf_event() { }

        void capture_start();
        void capture_end();
        std::string get_name() { return this->name_; }

    private:
        std::string name_;
        struct timespec start_ns_;
        struct timespec end_ns_;
};

class perf_linux {
    public:
        static perf_linux *instance() {
            static perf_linux p;
            return &p;
        }
        std::shared_ptr<perf_event> add_event(const std::string &event);
        std::shared_ptr<perf_event> get_event(const std::string &event);
        ~perf_linux() { }

    private:
        explicit perf_linux() { }
        std::vector<std::shared_ptr<perf_event>> events_;
};

}

}

#endif
