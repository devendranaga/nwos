#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "network_config.h"
#include "rng_linux.h"
#include "event_mgr.h"
#include "event_intf.h"
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

/**
 * @brief - Write event data to file.
 *
 * @param [in] fd - event file descriptor.
 * @param [in] evt_info - event info structure.
 */
static void event_storage_write_file(int fd,
                                     const event_info *evt_info)
{
    event_intf_hdr info;

    info.version                    = NETOS_EVENT_INTF_INFO_VERSION;
    info.info.tv_sec                = evt_info->detection_tv_sec;
    info.info.tv_usec               = evt_info->detection_tv_usec;
    info.info.event_type            = (uint32_t)(evt_info->event_type);
    info.info.event_protocol_level  = (uint32_t)(evt_info->protocol_level);
    info.info.event_description     = (uint32_t)(evt_info->event_desc);
    info.info.pkt_len               = evt_info->pkt_len;

    write(fd, (uint8_t *)&info, sizeof(info));
}

void event_mgr::event_storage_thread()
{
    network_config *conf;
    char event_filename[256];
    int rng_fd;
    uint32_t rng_val;
    int fd;

    rng_fd = netos_rng_init();
    netos_rng_get_bytes(rng_fd, (uint8_t *)&rng_val, sizeof(rng_val));

    conf = network_config::instance();

    snprintf(event_filename,
             sizeof(event_filename),
             "%s_event_data_%u.bin",
             conf->ids_config_.event_config.event_storage_path.c_str(),
             rng_val);


    fd = open(event_filename, O_WRONLY | O_CREAT, S_IRWXU);
    if (fd < 0) {
        return;
    }

    while (1) {
        std::unique_lock<std::mutex> l(this->evt_q_lock_);
        this->evt_q_cond_.wait(l);

        while (1) {
            event_info evt_info;

            if (this->event_info_queue_.empty()) {
                break;
            }

            evt_info = this->event_info_queue_.front();
            event_storage_write_file(fd, &evt_info);
            this->event_info_queue_.pop();
        }
    }
}

void event_mgr::insert_event(uint8_t event_type,
                             event_description desc,
                             event_protocol_level proto_level,
                             uint32_t pkt_len)
{
    struct timespec detection_ts;
    event_info evt_info;

    clock_gettime(CLOCK_REALTIME, &detection_ts);

    evt_info.event_type         = event_type;
    evt_info.detection_tv_sec   = detection_ts.tv_sec;
    evt_info.detection_tv_usec  = detection_ts.tv_nsec / 1000;
    evt_info.event_desc         = desc;
    evt_info.protocol_level     = proto_level;
    evt_info.pkt_len            = pkt_len;

    std::unique_lock<std::mutex> l(this->evt_q_lock_);
    this->event_info_queue_.push(evt_info);
    this->evt_q_cond_.notify_one();
}

}

