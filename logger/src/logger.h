#ifndef NETOS_LOGGER_SRC_LOGGER_H
#define NETOS_LOGGER_SRC_LOGGER_H

#include <sys/socket.h>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

#include "udp_socket.h"
#include "logging_protocol.h"

using namespace netos::lib;

namespace netos {

namespace logging {

struct log_buffer {
    uint8_t buf[4096];
};

struct logger_config {
    bool log_to_file;
    std::string log_file_name;
    bool log_to_console;
    bool log_to_syslog;

    static logger_config *instance() {
        static logger_config conf;
        return &conf;
    }
    ~logger_config() { }
    int parse(const std::string &config_file);
};

/**
 * @brief - Defines base Logger class.
 */
class logger {
    public:
        explicit logger(int argc, char **argv);
        ~logger();

        void run();

    private:
        void rx_thread();
        void log_thread();
        void log_to_file(netos_log_info *info_msg);
        void log_to_console(netos_log_info *info_msg);
        void log_to_syslog(netos_log_info *info_msg);

        char *config_server_ip_;
        int config_server_port_;
        char *config_file_;

        bool initialized_;
        FILE *log_fp_;
        std::shared_ptr<std::thread> rx_thread_;
        std::shared_ptr<std::thread> log_thread_;
        std::shared_ptr<udp_server_socket> server_socket_;
        std::queue<log_buffer> log_queue_;
        std::mutex log_queue_lock_;
        std::condition_variable log_queue_cond_;
};

}

}

#endif

