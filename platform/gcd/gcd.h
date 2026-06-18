#ifndef NETOS_GCD_H
#define NETOS_GCD_H

#include <stdint.h>

typedef void (*netos_timer_callback)(void *ctx);
typedef void (*netos_socket_callback)(int fd, void *ctx);

typedef struct netos_gcd_timer {
    uint64_t                sec;
    uint64_t                nsec;
    void                    *timer_ctx;
    netos_timer_callback    timer_cb;
    int                     fd;
    struct netos_gcd_timer  *next;
} netos_gcd_timer_t;

typedef struct {
    netos_gcd_timer_t       *timers;
} netos_gcd_timer_ctx_t;

typedef struct netos_gcd_socket {
    int                     fd;
    void                    *sock_ctx;
    netos_socket_callback   sock_cb;
    struct netos_gcd_socket *next;
} netos_gcd_socket_t;

typedef struct {
    netos_gcd_socket_t      *sockets;
} netos_gcd_socket_ctx_t;

typedef struct {
    int                     epoll_fd;
    netos_gcd_timer_ctx_t   timer_ctx;
    netos_gcd_socket_ctx_t  socket_ctx;
} netos_gcd_ctx_t;

netos_gcd_ctx_t *netos_gcd_ctx_init();

netos_status_t netos_gcd_socket_set_callback(netos_gcd_ctx_t *gcd_ctx,
                                             int fd,
                                             void *sock_ctx,
                                             netos_socket_callback callback);

netos_status_t netos_gcd_timer_set_callback(netos_gcd_ctx_t *gcd_ctx,
                                            uint64_t sec,
                                            uint64_t nsec,
                                            void *timer_ctx,
                                            netos_timer_callback callback);

void netos_gcd_run(netos_gcd_ctx_t *gcd_ctx);

#endif

