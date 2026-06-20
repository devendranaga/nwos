#ifndef NETWORK_MAIN_H
#define NETWORK_MAIN_H

#include <pthread.h>

#include "raw_socket.h"
#include "netos_config.h"
#include "pthread_intf.h"
#include "buffer_pool.h"
#include "event_mgr.h"
#include "parser_thread_ctx.h"
#include "packet_parser.h"
#include "egress_controller.h"
#include "interface_stats.h"
#include "queue.h"
#include "gcd.h"

typedef struct netos_cmdargs {
    char *config_file;
} netos_cmdargs_t;

/**
 * @brief - Defines a network interface context.
 */
typedef struct netos_intf {
    char                        *ifname;
    // initialized raw socket
    raw_socket_ctx_t            *raw;

    // recieve thread
    pthread_t                   rx_thread;

    // parser thread context
    netos_parser_thread_t       *parser_thr;

    // next interface in the list
    struct netos_intf           *next;
} netos_intf_t;

typedef struct netos_ctx {
    netos_cmdargs_t     cmdargs;
    network_config_t    config;
    netos_intf_t        *interfaces;
    netos_gcd_ctx_t     *gcd_ctx;
} netos_ctx_t;

#endif

