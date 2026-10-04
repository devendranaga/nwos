#ifndef NETOS_NDP_H
#define NETOS_NDP_H

#include <time.h>
#include <sys/time.h>

#include "protocol_const.h"
#include "hash_tables.h"
#include "netos_config.h"
#include "packet_parser.h"

#define NETOS_NDP_CACHE_MAX_LEN 64

typedef struct netos_ndp_ip6addr {
    uint8_t                     ip6addr[NETOS_IPV6_ADDR_LEN];

    struct netos_ndp_ip6addr    *next;
} netos_ndp_ip6addr_t;

typedef struct netos_ndp_entry {
    // each mac address could have multiple ipv6 addresses.
    // this is because there can be multiple ipv6 addresses per physical interface.
    // so a hash function based on mac could give multiple addresses.
    uint8_t             mac[NETOS_MACADDR_LEN];
    netos_ndp_ip6addr_t *ip6addr_list;

    // when was this entry updated (NA updates this)
    struct timeval      last_updated;
} netos_ndp_entry_t;

typedef struct {
    netos_config_t      *config;

    // entries of type netos_ndp_entry_t
    netos_hash_table_t  *ndp_cache;
} netos_ndp_ctx_t;

void *netos_ndp_init(netos_config_t *config);

void netos_ndp_rx(void *ctx,
                  netos_packet_parser_t *pkt_parser,
                  pkt_buffer_t *pkt_buf);

#endif

