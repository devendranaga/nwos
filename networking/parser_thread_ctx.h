#ifndef NETOS_PARSER_THREAD_CTX_H
#define NETOS_PARSER_THREAD_CTX_H

#include <stdbool.h>
#include <pthread.h>
#include "buffer_pool.h"
#include "raw_socket.h"
#include "packet_parser.h"
#include "ring.h"
#include "interface_stats.h"
#include "arp.h"

typedef struct netos_protocol_context {
    netos_packet_parser_t       parsed_data;
} netos_protocol_context_t;

typedef struct netos_parser_thread {
    char                        *ifname;
    raw_socket_ctx_t            *raw;
    pthread_t                   tid;
    pthread_mutex_t             parse_q_lock;
    pthread_cond_t              parse_q_cond;
    // receive buffer pool
    netos_buffer_pool_t         *rx_pool;
    netos_ring_t                parse_ring;
    netos_interface_stats_t     if_stats;
    netos_protocol_context_t    protocol_ctx;
} netos_parser_thread_t;

#define NETOS_TO_ARP_CTX(__this_ptr) (&(((netos_parser_thread_t *)__this_ptr)->protocol_ctx.arp))

#endif
