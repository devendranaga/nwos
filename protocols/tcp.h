#ifndef NETOS_TCP_H
#define NETOS_TCP_H

#include <time.h>
#include <sys/time.h>
#include "hash_tables.h"
#include "netos_status.h"
#include "netos_config.h"
#include "packet_parser.h"
#include "ipv6_hdr.h"

// Maximum possible connections that we can track right now
#define NETOS_TCP_CONN_LIST_MAX 320

/**
 * @brief - Defines the TCP states.
 */
typedef enum {
    NETOS_TCP_STATE_INIT = 1,
    NETOS_TCP_STATE_CLIENT_SENT_SYN,
    NETOS_TCP_STATE_SERVER_SENT_SYN_ACK,
    NETOS_TCP_STATE_CONN_ESTABLISHED,
    NETOS_TCP_STATE_FIN_SENT,
    NETOS_TCP_STATE_FIN_ACK_SENT,
    NETOS_TCP_STATE_CLOSED,
} netos_tcp_state_t;

/**
 * @brief - Defines a TCP connection.
 */
typedef struct netos_tcp_connection {
    bool                        is_ipv4;
    union {
        struct {
            uint32_t            src_ip;
            uint32_t            dst_ip;
        } v4;
        struct {
            uint8_t             src_ip[NETOS_IPV6_ADDR_LEN];
            uint8_t             dst_ip[NETOS_IPV6_ADDR_LEN];
        } v6;
    };
    struct timeval              last_updated;
    uint32_t                    seq_no;
    uint32_t                    ack_no;
    uint16_t                    src_port;
    uint16_t                    dst_port;
    netos_tcp_state_t           state;

    struct netos_tcp_connection *next;
} netos_tcp_connection_t;

/**
 * @brief - Defines TCP connection key.
 */
typedef struct netos_tcp_conn_key {
    uint8_t             protocol;
    bool                is_ipv4;
    union {
        struct {
            uint32_t    src_ip;
            uint32_t    dst_ip;
        } v4;
        struct {
            uint8_t     src_ip[NETOS_IPV6_ADDR_LEN];
            uint32_t    dst_ip[NETOS_IPV6_ADDR_LEN];
        } v6;
    };
    uint16_t            src_port;
    uint16_t            dst_port;
} netos_tcp_conn_key_t;

/**
 * @brief - Defines TCP context.
 */
typedef struct {
    // user config
    netos_config_t      *config;
    // list of TCP connections
    netos_hash_table_t  *conn_list;
} netos_tcp_context_t;

void *netos_tcp_initialize(netos_config_t *config);

void netos_tcp_rx_process(void *ctx,
                          netos_packet_parser_t *pkt_parser,
                          pkt_buffer_t *pkt_buf);

void netos_tcp_tx_process(void *ctx,
                          pkt_buffer_t *pkt_buf);

void netos_tcp_deinit(void *ctx);

#endif

