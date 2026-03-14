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
#include <parsed_pkt.h>
#include <pcap_lib.h>
#include <fileio_mem.h>

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
        explicit pcap_mod() : terminate_(false), filesize_bytes_(0) { }
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
        void add_packet(parsed_pkt *pkt);

        void terminate() {
            std::unique_lock<std::mutex> l(this->pkt_queue_lock_);

            this->terminate_ = true;

            printf("set terminate to true\n");
            this->pkt_queue_cond_.notify_one();
        }

    private:
        std::shared_ptr<pcap_writer> pcap_wr_;
        std::queue<parsed_pkt *> pkt_queue_;
        std::mutex pkt_queue_lock_;
        std::condition_variable pkt_queue_cond_;
        std::shared_ptr<std::thread> pcap_thr_;
        bool terminate_;
        uint32_t filesize_bytes_;

        /**
         * Process the frame.
         * 1. Waits on the condition.
         * 2. dequeue each frame and calls pcap_wr_->write_packet.
         */
        void pcap_thread();
        netos_status make_filename(const std::string &pcap_filename,
                                   const std::string &ifname,
                                   std::string &filename_str);
};

}

#endif

