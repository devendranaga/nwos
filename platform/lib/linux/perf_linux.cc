#include "perf_linux.h"

namespace netos {

namespace lib {

void perf_event::capture_start()
{
    clock_gettime(CLOCK_REALTIME, &this->start_ns_);
}

void perf_event::capture_end()
{
    double diff;

    clock_gettime(CLOCK_REALTIME, &this->end_ns_);

    struct timespec diff_tv = {
        .tv_sec = this->end_ns_.tv_sec - this->start_ns_.tv_sec, //
        .tv_nsec = this->end_ns_.tv_nsec - this->start_ns_.tv_nsec
    };

    diff = (diff_tv.tv_sec * 1000000) + (diff_tv.tv_nsec / 1000);
    printf(" took %f sec\n", diff / 1000000.0);
}

std::shared_ptr<perf_event> perf_linux::add_event(const std::string &event)
{
    std::shared_ptr<perf_event> p;

    p = std::make_shared<perf_event>(event);
    this->events_.push_back(p);
    return p;
}

std::shared_ptr<perf_event> perf_linux::get_event(const std::string &event)
{
    for (auto &it : this->events_) {
        if (it->get_name() == event) {
            return it;
        }
    }
    return nullptr;
}

}

}
