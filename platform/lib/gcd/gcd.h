#ifndef PLATFORM_LIB_GCD_H
#define PLATFORM_LIB_GCD_H

#include <vector>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <queue>

#include <sys/select.h>
#include "error_codes.h"

using namespace netos::lib;

namespace netos {

typedef std::function<void()>       timer_callback;
typedef std::function<void(int)>    socket_callback;
typedef std::function<void()>       task_callback;
typedef std::function<void()>       term_callback;

/**
 * @brief - Implements worker thread class.
 */
class gcd_worker_thread {
    public:
        explicit gcd_worker_thread() = default;
        ~gcd_worker_thread() = default;

        void initialize(uint32_t thread_id);
        void queue_task(task_callback &cb);

    private:
        void worker_thread();

        uint32_t thread_id_;
        std::shared_ptr<std::thread> thread_;
        std::mutex lock_;
        std::condition_variable cond_;
        std::queue<task_callback> task_queue_;
};

class gcd_thread_pool {
    public:
        explicit gcd_thread_pool() = default;
        ~gcd_thread_pool() = default;

        void initialize(uint32_t n_threads);
        void queue_task(task_callback &cb);

    private:
        std::vector<std::shared_ptr<gcd_worker_thread>> threads_;
        uint32_t next_worker_id_;
        uint32_t n_threads_;
};

class gcd_timer {
    public:
        explicit gcd_timer() = default;
        ~gcd_timer() = default;

        netos_status initialize(uint32_t sec, uint64_t nsec, timer_callback &cb);
        void deinitialize();
        int get_fd() { return this->timer_fd_; }
        timer_callback get_cb() { return this->cb_; }

    private:
        uint32_t sec_;
        uint64_t nsec_;
        timer_callback cb_;
        int timer_fd_;
};

class gcd_socket {
    public:
        explicit gcd_socket() = default;
        ~gcd_socket() = default;

        int initialize(int fd, socket_callback &cb);
        int get_fd() { return this->fd_; }
        socket_callback get_cb() { return this->cb_; }

    private:
        int fd_;
        socket_callback cb_;
};

class gcd {
    public:
        static gcd *instance()
        {
            static gcd instance;
            return &instance;
        }
        ~gcd();

        inline void initialize()
        {
            FD_ZERO(&this->allfd_);
            this->max_fd_ = -1;
            this->terminate_ = false;
        }

        /**
         * @brief - Initialize the thread pool given the number of threads.
         *
         * @param [in] n_threads - Number of threads.
         */
        void initialize_thr_pool(uint32_t n_threads);

        /**
         * @brief - Register a periodic timer.
         *
         * @param [in] sec - Seconds.
         * @param [in] nsec - Nanoseconds.
         * @param [in] cb - Callback.
         */
        netos_status register_timer(uint32_t sec, uint64_t nsec, timer_callback &cb);

        /**
         * @brief - Register a socket.
         *
         * @param [in] fd - File descriptor.
         * @param [in] cb - Callback.
         */
        void register_socket(int fd, socket_callback &cb);

        void register_term_signal(term_callback &cb);

        /**
         * @brief - Queue a work.
         *
         * @param [in] cb - Callback.
         */
        void queue_work(task_callback &cb);

        /**
         * @brief - Run the GCD.
         */
        void run();

        void terminate();

    private:
        explicit gcd() { }
        gcd(const gcd &other) = delete;
        gcd &operator=(const gcd &other) = delete;

        std::vector<gcd_timer> timers_;
        std::vector<gcd_socket> sockets_;
        term_callback term_cb_;
        gcd_thread_pool thr_pool_;
        int sig_fd_;
        int max_fd_;
        fd_set allfd_;
        bool terminate_;
};

}

#endif

