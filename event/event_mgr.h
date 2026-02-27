#ifndef IDS_EVENT_EVENT_MGR_H
#define IDS_EVENT_EVENT_MGR_H

#include <memory>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

#include "event_info.h"

namespace netos {

class event_mgr {
    public:
        ~event_mgr() = default;
        static event_mgr *instance() {
            static event_mgr evt_mgr;
            return &evt_mgr;
        }

        /**
         * @brief - Initialize event manager.
         */
        void initialize();

        /**
         * @brief - insert event into the event queue.
         */
        void insert_event(uint8_t event_type,
                          event_description desc,
                          event_protocol_level proto_level,
                          uint32_t pkt_len);

    private:
        void event_forwarding_timer();
        void event_storage_thread();

        std::shared_ptr<std::thread> event_storage_thr_;
        std::queue<event_info> event_info_queue_;
        std::mutex evt_q_lock_;
        std::condition_variable evt_q_cond_;
        explicit event_mgr() = default;
};

}

#endif

