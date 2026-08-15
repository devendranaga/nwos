#ifndef NETOS_PROTOCOLS_ARP_H
#define NETOS_PROTOCOLS_ARP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>

#include "protocol_const.h"
#include "netos_status.h"
#include "netos_config.h"
#include "buffer_pool.h"
#include "pkt_buffer.h"
#include "gcd.h"
#include "arp_hdr.h"
#include "packet_parser.h"
#include "hash_tables.h"

typedef struct netos_arp_mib {
    uint64_t    in_arp;
    uint64_t    in_arp_invalid;
    uint64_t    in_arp_valid;
} netos_arp_mib_t;

typedef struct netos_arp_entry {
    uint8_t                 mac[NETOS_MACADDR_LEN];
    netos_raw_socket_ctx_t  *in_intf; // where this entry reside on
    uint32_t                ipaddr;
    struct timespec         last_updated;
} netos_arp_entry_t;

typedef struct netos_arp_protocol {
    netos_config_t *config;
    netos_arp_mib_t mib;
    netos_hash_table_t *arp_cache;
    pthread_mutex_t lock;
    netos_buffer_pool_t *pool;
} netos_arp_protocol_t;

netos_status_t netos_arp_rx_process(pkt_buffer_t *pkt_buf,
                                    netos_packet_parser_t *pkt_parser);

netos_status_t netos_arp_protocol_init(netos_config_t *config,
                                       netos_gcd_ctx_t *gcd_ctx);

void netos_arp_mib_in_arp_ok();

void netos_arp_mib_in_arp_invalid();

#if defined(__cplusplus)
}
#endif

#endif

