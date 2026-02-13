#include "perf_linux.h"

namespace netos {

namespace lib {

void perf_event::capture_start()
{
    clock_gettime(CLOCK_MONOTONIC, &this->start_ns_);
}

void perf_event::capture_end()
{
    double delta_ns;

    clock_gettime(CLOCK_MONOTONIC, &this->end_ns_);
    delta_ns = (this->end_ns_.tv_sec - this->start_ns_.tv_sec) * 1000000000 +
               (this->end_ns_.tv_nsec - this->start_ns_.tv_nsec);

    this->perf_data_.push_back(delta_ns);
}

double perf_event::average()
{
    double sum = 0;
    for (auto &it : this->perf_data_) {
        sum += it;
    }
    return sum / this->perf_data_.size();
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
