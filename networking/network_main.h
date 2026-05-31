#ifndef NETWORK_MAIN_H
#define NETWORK_MAIN_H

#include <pthread.h>

#include "raw_socket.h"
#include "network_config.h"
#include "pthread_intf.h"
#include "buffer_pool.h"
#include "packet_parser.h"
#include "queue.h"

typedef struct netos_cmdargs {
    char *config_file;
} netos_cmdargs_t;

typedef struct netos_parser_thread {
    char                    *ifname;
    raw_socket_ctx_t        *raw;
    pthread_t               tid;
    pthread_mutex_t         parse_q_lock;
    pthread_cond_t          parse_q_cond;
    netos_queue_impl_t      *parse_q;
    netos_packet_parser_t   parsed_data;
} netos_parser_thread_t;

typedef struct netos_intf {
    char                    *ifname;
    raw_socket_ctx_t        *raw;
    pthread_t               rx_thread;
    netos_buffer_pool_t     *rx_pool;
    netos_parser_thread_t   *parser_thr;
    struct netos_intf       *next;
} netos_intf_t;

typedef struct netos_ctx {
    netos_cmdargs_t     cmdargs;
    network_config_t    config;
    netos_intf_t        *interfaces;
} netos_ctx_t;

#endif

