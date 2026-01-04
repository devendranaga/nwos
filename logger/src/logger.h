#ifndef NETOS_LOGGER_SRC_LOGGER_H
#define NETOS_LOGGER_SRC_LOGGER_H

#include <sys/socket.h>
#include <memory>
#include <thread>
#include <mutex>

namespace netos {

namespace logging {

class logger {
    public:
        explicit logger(int argc, char **argv);
        ~logger();

        void run();

    private:
        void rx_thread();

        char *config_server_ip_;
        int config_server_port_;

        bool initialized_;
        int server_fd_;
        std::shared_ptr<std::thread> rx_thread_;
};

}

}

#endif

