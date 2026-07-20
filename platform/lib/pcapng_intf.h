#ifndef NETOS_PCAPNG_INTF_H
#define NETOS_PCAPNG_INTF_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t    original_len;
    uint32_t    captured_len;
    uint8_t     *pkt;
} netos_pcapng_frame_t;

typedef enum {
    NETOS_PCAPNG_OP_READ = 1,
} netos_pcapng_op_t;

typedef struct {
    char    *ifname;
    char    *ifdesc;
    uint8_t ts_resol;
    char    *iffilter;
    char    *os;
    uint8_t fcs_len;
} netos_pcapng_idb_opt_t;

typedef struct {
    uint16_t                link_type;
    uint32_t                snaplen;
    netos_pcapng_idb_opt_t  idb_opt;
} netos_pcapng_idb_t;

typedef struct {
    uint32_t secrets_type;
    uint32_t secrets_length;
    uint8_t *secrets_data;
} netos_pcapng_dsb_t;

typedef struct {
    uint16_t rec_type;
    uint16_t rec_len;
    uint8_t *rec;
} netos_pcapng_nrb_t;

typedef struct {
    uint32_t    intf_id;
    uint32_t    ts_high;
    uint32_t    ts_low;
    uint32_t    captured_len;
    uint32_t    original_len;
    uint8_t     *pkt_data;
} netos_pcapng_epb_t;

typedef struct {
    uint32_t    original_len;
    uint8_t     *packet_data;
} netos_pcapng_spb_t;

typedef struct {
    bool                big_endian;
    char                *comment;
    char                *hw;
    char                *os;
    char                *app;
    netos_pcapng_idb_t  idb;
    netos_pcapng_epb_t  epb;
    netos_pcapng_dsb_t  dsb;
    netos_pcapng_nrb_t  nrb;
    netos_pcapng_spb_t  spb;
} netos_pcapng_file_record_t;

typedef struct {
    bool is_ipv4;
    union {
        uint32_t ipaddr;
        uint8_t ip6addr[16];
    } bytes;
    char *ipaddr_str;
} netos_pcapng_dns_lookup_data_t;

#define NETOS_DNS_LOOKUP_DATA_INIT(__data) do {\
    (__data).is_ipv4 = false;\
    (__data).bytes.ipaddr = 0;\
    (__data).bytes.ip6addr[0] = 0;\
    (__data).bytes.ip6addr[1] = 0;\
    (__data).bytes.ip6addr[2] = 0;\
    (__data).bytes.ip6addr[3] = 0;\
    (__data).bytes.ip6addr[4] = 0;\
    (__data).bytes.ip6addr[5] = 0;\
    (__data).bytes.ip6addr[6] = 0;\
    (__data).bytes.ip6addr[7] = 0;\
    (__data).bytes.ip6addr[8] = 0;\
    (__data).bytes.ip6addr[9] = 0;\
    (__data).bytes.ip6addr[10] = 0;\
    (__data).bytes.ip6addr[11] = 0;\
    (__data).bytes.ip6addr[12] = 0;\
    (__data).bytes.ip6addr[13] = 0;\
    (__data).bytes.ip6addr[14] = 0;\
    (__data).bytes.ip6addr[15] = 0;\
    (__data).ipaddr_str = NULL;\
} while (0)

typedef void (*netos_pcapng_parse_cb)(void *ctx, netos_pcapng_frame_t *frame);
typedef void (*netos_pcapng_dns_lookup_cb)(void *ctx, netos_pcapng_dns_lookup_data_t *dns_data);

typedef struct {
    netos_pcapng_parse_cb       parse_cb;
    netos_pcapng_dns_lookup_cb  dns_cb;
} netos_pcapng_parse_callbacks_t;

typedef struct {
    int                             fd;
    void                            *mapped_memory;
    void                            *user_ctx;
    uint32_t                        offset;
    netos_pcapng_file_record_t      rec;
    netos_pcapng_parse_callbacks_t  *parse_cb_data;
} netos_pcapng_ctx_t;

netos_pcapng_ctx_t *netos_pcapng_ctx_parse(netos_pcapng_op_t op,
                                           const char *filename,
                                           void *ctx,
                                           netos_pcapng_parse_callbacks_t *parse_cb);

#endif

