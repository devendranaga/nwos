#include "network_config.h"
#include "event_mgr.h"
#include "gcd.h"

using namespace netos::lib;

namespace netos {

void event_mgr::initialize()
{
    network_config *config;
    gcd *gcd_instance;

    gcd_instance = gcd::instance();
    config = network_config::instance();

    if (config->ids_config_.event_config.event_fwd_enable) {
        std::function<void()> fwd_timer = std::bind(&event_mgr::event_forwarding_timer, this);

        gcd_instance->register_timer(0,
                                     config->ids_config_.event_config.timer_period_ms * 1000000,
                                     fwd_timer);
    }

    if (config->ids_config_.event_config.event_storage_enable) {
        this->event_storage_thr_ = std::make_shared<std::thread>(
                                        &event_mgr::event_storage_thread,
                                        this);
        this->event_storage_thr_->detach();
    }
}

void event_mgr::event_forwarding_timer()
{
}

void event_mgr::event_storage_thread()
{
    while (1) {
        std::unique_lock<std::mutex> l(this->evt_q_lock_);
        this->evt_q_cond_.wait(l);

        while (1) {
            event_info evt_info;

            if (this->event_info_queue_.empty()) {
                break;
            }

            evt_info = this->event_info_queue_.front();
            this->event_info_queue_.pop();
        }
    }
}

void event_mgr::insert_event(uint8_t event_type,
                             event_description desc,
                             event_protocol_level proto_level,
                             uint32_t pkt_len)
{
    event_info evt_info;

    evt_info.event_type = event_type;
    evt_info.event_desc = desc;
    evt_info.protocol_level = proto_level;
    evt_info.pkt_len = pkt_len;

    std::unique_lock<std::mutex> l(this->evt_q_lock_);
    this->event_info_queue_.push(evt_info);
    this->evt_q_cond_.notify_one();
}

}

