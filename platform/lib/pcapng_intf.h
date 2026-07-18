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
    uint16_t link_type;
    uint32_t snaplen;
} netos_pcapng_idb_t;

typedef struct {
    uint32_t    intf_id;
    uint32_t    ts_high;
    uint32_t    ts_low;
    uint32_t    captured_len;
    uint32_t    original_len;
    uint8_t     *pkt_data;
} netos_pcapng_epb_t;

typedef struct {
    bool                big_endian;
    netos_pcapng_idb_t  idb;
    netos_pcapng_epb_t  epb;
} netos_pcapng_file_record_t;

typedef void (*netos_pcapng_parse_cb)(void *ctx, netos_pcapng_frame_t *frame);

typedef struct {
    int                         fd;
    void                        *mapped_memory;
    void                        *user_ctx;
    uint32_t                    offset;
    netos_pcapng_file_record_t  rec;
    netos_pcapng_parse_cb       parse_cb;
} netos_pcapng_ctx_t;

netos_pcapng_ctx_t *netos_pcapng_ctx_parse(netos_pcapng_op_t op,
                                           const char *filename,
                                           void *ctx,
                                           netos_pcapng_parse_cb parse_cb);

#endif

