#ifndef IDS_EVENT_EVENT_MGR_H
#define IDS_EVENT_EVENT_MGR_H

#include <queue>
#include <mutex>

#include "event_info.h"

namespace netos {

namespace ids {

class event_mgr {
    public:
        ~event_mgr() = default;
        static event_mgr *instance() {
            static event_mgr evt_mgr;
            return &evt_mgr;
        }

        void insert_event(uint8_t event_type,
                          event_description desc,
                          event_protocol_level proto_level,
                          uint32_t pkt_len);

    private:
        std::queue<event_info> event_info_queue_;
        std::mutex evt_q_lock_;
        explicit event_mgr() = default;
};

}

}

#endif

