#ifndef NETOS_PCAPNG_INTF_H
#define NETOS_PCAPNG_INTF_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t original_len;
    uint32_t capture_len;
    uint8_t *pkt;
    uint32_t pkt_len;
} netos_pcapng_frame_t;

typedef enum {
    NETOS_PCAPNG_OP_READ = 1,
} netos_pcapng_op_t;

typedef struct {
    bool big_endian;
} netos_pcapng_file_record_t;

typedef struct {
    int fd;
    void *mapped_memory;
    uint32_t offset;
    netos_pcapng_file_record_t rec;
    void (*parse_callback)(netos_pcapng_frame_t *frame);
} netos_pcapng_ctx_t;

netos_pcapng_ctx_t *netos_pcapng_ctx_init(netos_pcapng_op_t op, const char *filename);

#endif

