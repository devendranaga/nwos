#ifndef NETWORKING_PCAP_H
#define NETWORKING_PCAP_H

#include <string>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <stdint.h>
#include <time.h>

#include <error_codes.h>
#include <packet_buf.h>
#include <pcap_lib.h>

using namespace netos::lib;

namespace netos {

/**
 * Defines a PCAP module interface.
 *
 * helper class that can log to a pcap file.
 * runs a thread that writes to the file so that the caller does not block.
 *
 * caller has to queue in the packet buffer and the thread will be woken up to
 * perform the writes.
 */
class pcap_mod {
    public:
        explicit pcap_mod() { }
        ~pcap_mod() { }

        /**
         * Initializes the pcap module.
         * Following tasks are done:
         * 1. create filename : config_filename_ifname_yyyy_mm_dd_hh_mm_ss.pcap
         * 2. create a thread and waits it for the frames.
         */
        netos_status initialize(const std::string &ifname,
                                const std::string &pcap_filename);

        /**
         * Queue the frame to the packet queue.
         */
        void add_packet(packet_buf *pkt);

    private:
        std::shared_ptr<pcap_writer> pcap_wr_;
        std::queue<packet_buf *> pkt_queue_;
        std::mutex pkt_queue_lock_;
        std::condition_variable pkt_queue_cond_;
        std::shared_ptr<std::thread> pcap_thr_;

        /**
         * Process the frame.
         * 1. Waits on the condition.
         * 2. dequeue each frame and calls pcap_wr_->write_packet.
         */
        void pcap_thread();
};

}

#endif
