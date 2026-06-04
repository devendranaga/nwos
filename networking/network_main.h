#ifndef NETWORK_MAIN_H
#define NETWORK_MAIN_H

#include <pthread.h>

#include "raw_socket.h"
#include "network_config.h"
#include "pthread_intf.h"
#include "buffer_pool.h"
#include "parser_thread_ctx.h"
#include "packet_parser.h"
#include "egress_controller.h"
#include "interface_stats.h"
#include "queue.h"

typedef struct netos_cmdargs {
    char *config_file;
} netos_cmdargs_t;

typedef struct netos_intf {
    char                        *ifname;
    raw_socket_ctx_t            *raw;
    pthread_t                   rx_thread;
    netos_buffer_pool_t         *rx_pool;
    netos_parser_thread_t       *parser_thr;
    netos_egress_controller_t   *egress_ctrl;
    struct netos_intf           *next;
} netos_intf_t;

typedef struct netos_ctx {
    netos_cmdargs_t     cmdargs;
    network_config_t    config;
    netos_intf_t        *interfaces;
} netos_ctx_t;

#endif

