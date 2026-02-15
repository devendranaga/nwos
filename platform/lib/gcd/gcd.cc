#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/timerfd.h>

#include "gcd.h"
#include "error_codes.h"

using namespace netos::lib;

namespace netos {

netos_status gcd_timer::initialize(uint32_t sec, uint64_t nsec, timer_callback &cb)
{
    struct itimerspec timer_val;
    int ret;

    /* Default initialize with the reload option. */
    timer_val.it_value.tv_sec           = sec;
    timer_val.it_value.tv_nsec          = nsec;
    timer_val.it_interval.tv_sec        = sec;
    timer_val.it_interval.tv_nsec       = nsec;

    this->sec_  = sec;
    this->nsec_ = nsec;
    this->cb_   = cb;

    /* Create the timer. */
    this->timer_fd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (this->timer_fd_ < 0) {
        return netos_status::NETOS_STATUS_TIMERFD_CREATE_FAIL;
    }

    /* Set the timer. */
    ret = timerfd_settime(this->timer_fd_, 0, &timer_val, NULL);
    if (ret < 0) {
        close(this->timer_fd_);
        return netos_status::NETOS_STATUS_TIMERFD_SETTIME_FAIL;
    }

    return netos_status::NETOS_STATUS_SUCCESS;
}

int gcd_socket::initialize(int fd, socket_callback &cb)
{
    this->fd_    = fd;
    this->cb_    = cb;

    return 0;
}

void gcd_thread_pool::initialize(uint32_t n_threads)
{
    uint32_t i;

    this->n_threads_ = n_threads;
    this->next_worker_id_ = 0;

    for (i = 0; i < n_threads; i ++) {
        std::shared_ptr<gcd_worker_thread> worker_thr;

        worker_thr = std::make_shared<gcd_worker_thread>();
        worker_thr->initialize();
        this->threads_.emplace_back(worker_thr);
    }
}

void gcd_worker_thread::initialize()
{
    auto callback = std::bind(&gcd_worker_thread::worker_thread, this);

    this->thread_ = std::make_shared<std::thread>(callback);
    this->thread_->detach();
}

/**
 * @brief Worker thread function.
 *
 * This function is the main loop of the worker thread.
 * It waits for a notification from the main thread and then processes the task queue.
 *
 * Each callback executes until completion and dequeues the next task in queue.
 */
void gcd_worker_thread::worker_thread()
{
    while (1) {
        std::unique_lock<std::mutex> lock(this->lock_);
        this->cond_.wait(lock);

        while (this->task_queue_.empty() == false) {
            task_callback cb;

            cb = this->task_queue_.front();
            this->task_queue_.pop();
            cb();
        }
    }
}

void gcd_worker_thread::queue_task(task_callback &cb)
{
    std::unique_lock<std::mutex> lock(this->lock_);

    this->task_queue_.push(cb);
    this->cond_.notify_one();
}

void gcd_thread_pool::queue_task(task_callback &cb)
{
    uint32_t worker_id;

    worker_id = this->next_worker_id_ % this->n_threads_;
    this->threads_[worker_id]->queue_task(cb);
    this->next_worker_id_ ++;
}

netos_status gcd::register_timer(uint32_t sec, uint64_t nsec, timer_callback &cb)
{
    gcd_timer t;
    int timer_fd;
    netos_status ret;

    ret = t.initialize(sec, nsec, cb);
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    this->timers_.emplace_back(t);

    timer_fd = t.get_fd();
    if (timer_fd > this->max_fd_) {
        this->max_fd_ = timer_fd;
    }
    FD_SET(timer_fd, &this->allfd_);

    return netos_status::NETOS_STATUS_SUCCESS;
}

void gcd::register_socket(int fd, socket_callback &cb)
{
    gcd_socket s;

    s.initialize(fd, cb);
    this->sockets_.emplace_back(s);

    if (fd > this->max_fd_) {
        this->max_fd_ = fd;
    }
    FD_SET(fd, &this->allfd_);
}

void gcd::initialize_thr_pool(uint32_t n_threads)
{
    this->thr_pool_.initialize(n_threads);
}

void gcd::queue_work(task_callback &cb)
{
    this->thr_pool_.queue_task(cb);
}

void gcd::run()
{
    fd_set read_set;

    while (1) {
        int ret;

        read_set = this->allfd_;

        ret = select(this->max_fd_ + 1, &read_set, NULL, NULL, NULL);
        if (ret < 0) {
            return;
        }

        for (auto it : this->timers_) {
            if (FD_ISSET(it.get_fd(), &read_set)) {
                uint64_t read_val;

                ret = read(it.get_fd(), (uint8_t *)&read_val, sizeof(read_val));
                if (ret < 0) {
                    return;
                }
                auto cb = it.get_cb();
                cb();
            }
        }

        for (auto it : this->sockets_) {
            if (FD_ISSET(it.get_fd(), &read_set)) {
                auto cb = it.get_cb();
                cb(it.get_fd());
            }
        }
    }
}

}
