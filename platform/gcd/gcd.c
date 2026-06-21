#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <errno.h>
#include "netos_status.h"
#include "gcd.h"

#define NETOS_GCD_EPOLL_MAX_EVENTS 256

netos_gcd_ctx_t *netos_gcd_ctx_init()
{
    netos_gcd_ctx_t *gcd_ctx;

    gcd_ctx = calloc(1, sizeof(netos_gcd_ctx_t));
    if (!gcd_ctx) {
        return NULL;
    }

    gcd_ctx->epoll_fd = epoll_create1(0);
    if (gcd_ctx->epoll_fd < 0) {
        goto err;
    }
    gcd_ctx->socket_ctx.sockets = NULL;
    gcd_ctx->timer_ctx.timers = NULL;

    return gcd_ctx;

err:
    if (gcd_ctx) {
        free(gcd_ctx);
    }

    return NULL;
}

netos_status_t netos_gcd_socket_set_callback(netos_gcd_ctx_t *gcd_ctx,
                                             int fd,
                                             void *sock_ctx,
                                             netos_socket_callback callback)
{
    netos_gcd_socket_t *sock;

    sock = calloc(1, sizeof(netos_gcd_socket_t));
    if (!sock) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    sock->fd = fd;
    sock->sock_cb = callback;
    sock->sock_ctx = sock_ctx;

    if (!gcd_ctx->socket_ctx.sockets) {
        gcd_ctx->socket_ctx.sockets = sock;
    } else {
        sock->next = gcd_ctx->socket_ctx.sockets;
        gcd_ctx->socket_ctx.sockets = sock;
    }

    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.fd = fd;

    int ret = epoll_ctl(gcd_ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    if (ret < 0) {
        free(sock);
        return NETOS_STATUS_GCD_SOCK_REG_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_gcd_timer_set_callback(netos_gcd_ctx_t *gcd_ctx,
                                            uint64_t sec,
                                            uint64_t nsec,
                                            void *timer_ctx,
                                            netos_timer_callback callback)
{
    netos_gcd_timer_t *timer;
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    timer = calloc(1, sizeof(netos_gcd_timer_t));
    if (!timer) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    timer->sec = sec;
    timer->nsec = nsec;
    timer->timer_ctx = timer_ctx;
    timer->timer_cb = callback;

    struct itimerspec it = {
        .it_value = {
            .tv_sec = sec,
            .tv_nsec = nsec,
        },
        .it_interval = {
            .tv_sec = sec,
            .tv_nsec = nsec,
        }
    };
    timer->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timer->fd < 0) {
        ret = NETOS_STATUS_TIMERFD_CREATE_FAILURE;
        goto err;
    }

    int res = timerfd_settime(timer->fd, 0, &it, NULL);
    if (res != 0) {
        ret = NETOS_STATUS_TIMERFD_CREATE_FAILURE;
        goto err;
    }

    struct epoll_event ev;

    ev.events = EPOLLIN;
    ev.data.fd = timer->fd;

    res = epoll_ctl(gcd_ctx->epoll_fd, EPOLL_CTL_ADD, timer->fd, &ev);
    if (res != 0) {
        ret = NETOS_STATUS_GCD_SOCK_REG_FAILED;
        goto err;
    }

    if (!gcd_ctx->timer_ctx.timers) {
        gcd_ctx->timer_ctx.timers = timer;
    } else {
        timer->next = gcd_ctx->timer_ctx.timers;
        gcd_ctx->timer_ctx.timers = timer;
    }

    return NETOS_STATUS_SUCCESS;

err:
    if (timer) {
        if (timer->fd > 0) {
            close(timer->fd);
        }
        free(timer);
    }

    return ret;
}

static netos_status_t netos_gcd_run_timers(netos_gcd_ctx_t *gcd_ctx, struct epoll_event *event)
{
    netos_gcd_timer_ctx_t *timer_ctx = &gcd_ctx->timer_ctx;
    netos_gcd_timer_t *timer;

    for (timer = timer_ctx->timers; timer; timer = timer->next) {
        uint64_t counter;

        if (event->data.fd == timer->fd) {
            int ret = read(timer->fd, &counter, sizeof(counter));
            if (ret != sizeof(counter)) {
                break;
            }

            if (timer->timer_cb) {
                timer->timer_cb(timer->timer_ctx);
                return NETOS_STATUS_SUCCESS;
            }
        }
    }

    return NETOS_STATUS_GCD_TIMER_EVENT_UNHANDLED;
}

static netos_status_t netos_gcd_run_sockets(netos_gcd_ctx_t *gcd_ctx, struct epoll_event *event)
{
    netos_gcd_socket_ctx_t *sock_ctx = &gcd_ctx->socket_ctx;
    netos_gcd_socket_t *s;

    for (s = sock_ctx->sockets; s; s = s->next) {
        if (event->data.fd == s->fd) {
            if (s->sock_cb) {
                s->sock_cb(s->fd, s->sock_ctx);
                return NETOS_STATUS_SUCCESS;
            }
        }
    }

    return NETOS_STATUS_GCD_SOCKET_EVENT_UNHANDLED;
}

void netos_gcd_run(netos_gcd_ctx_t *gcd_ctx)
{
    struct epoll_event *events;
    int nfd;

    events = calloc(1, sizeof(struct epoll_event) * NETOS_GCD_EPOLL_MAX_EVENTS);
    if (!events) {
        return;
    }

    while (1) {
        netos_status_t ret;

        nfd = epoll_wait(gcd_ctx->epoll_fd, events, NETOS_GCD_EPOLL_MAX_EVENTS - 1, -1);
        if (nfd < 0) {
            if (errno == EINTR) {
                break;
            }
        }
        for (int i = 0; i < nfd; i ++) {
            if (events[i].events & EPOLLIN) {
                ret = netos_gcd_run_timers(gcd_ctx, &events[i]);
                if (ret != NETOS_STATUS_SUCCESS) {
                    ret = netos_gcd_run_sockets(gcd_ctx, &events[i]);
                }
            }
        }
    }
}

