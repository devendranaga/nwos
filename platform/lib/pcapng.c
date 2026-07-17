#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "netos_status.h"
#include "pcapng_intf.h"

#define NETOS_PCAPNG_ENDIAN_BE 0x4d3c2b1a
#define NETOS_PCAPNG_ENDIAN_LE 0x1a2b3c4d

typedef struct __attribute__ ((__packed__)) {
    uint32_t block_type;
    uint32_t block_total_len;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t section_len;
} netos_pcapng_shb_t;

// Simple compile-time endianness check
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // Big-endian: No transformation needed
    #define NETOS_NTOHL(x) ((uint32_t)(x))
#else
    // Little-endian: Mask and shift the bytes
    #define NETOS_NTOHL(x) ( \
        (((uint32_t)(x) & 0x000000FF) << 24) | \
        (((uint32_t)(x) & 0x0000FF00) << 8)  | \
        (((uint32_t)(x) & 0x00FF0000) >> 8)  | \
        (((uint32_t)(x) & 0xFF000000) >> 24)   \
    )
#endif


#if 0
static inline uint16_t netos_pcapng_get_u16(netos_pcapng_ctx_t *ctx)
{
    uint16_t val = 0;
    uint8_t *pkt = ctx->mapped_memory;

    if (ctx->rec.big_endian) {
        val = (pkt[ctx->offset] << 8) | (pkt[ctx->offset + 1]);
    } else {
        val = (pkt[ctx->offset + 1] << 8) | (pkt[ctx->offset]);
    }

    return val;
}
#endif

static inline uint32_t netos_pcapng_get_u32(netos_pcapng_ctx_t *ctx)
{
    uint32_t val = 0;
    uint8_t *pkt = ctx->mapped_memory;

    if (ctx->rec.big_endian) {
        val = (pkt[ctx->offset] << 24) |
              (pkt[ctx->offset + 1] << 16) |
              (pkt[ctx->offset + 2] << 8) |
              (pkt[ctx->offset + 3]);
    } else {
        val = (pkt[ctx->offset + 3] << 24) |
              (pkt[ctx->offset + 2] << 16) |
              (pkt[ctx->offset + 1] << 8) |
              (pkt[ctx->offset]);
    }

    return val;
}

static netos_status_t netos_pcapng_parse_shb(netos_pcapng_ctx_t *ctx,
                                             netos_pcapng_shb_t *shb)
{
    uint32_t val_32;

    val_32 = netos_pcapng_get_u32(ctx);
    printf("%x\n", val_32);

    return NETOS_STATUS_SUCCESS;
}

netos_pcapng_ctx_t *netos_pcapng_ctx_init(netos_pcapng_op_t op, const char *filename)
{
    netos_pcapng_ctx_t *ctx;
    struct stat st;
    int ret;

    ret = stat(filename, &st);
    if (ret != 0) {
        return NULL;
    }

    ctx = calloc(1, sizeof(netos_pcapng_ctx_t));
    if (!ctx) {
        return NULL;
    }

    if (op == NETOS_PCAPNG_OP_READ) {
        ctx->fd = open(filename, O_RDONLY);
        if (ctx->fd < 0) {
            goto err;
        }

        ctx->mapped_memory = mmap(NULL, st.st_size,
                                  PROT_READ,
                                  MAP_SHARED,
                                  ctx->fd,
                                  0);
        if (ctx->mapped_memory == MAP_FAILED) {
            // fallback to normal file i/o
            goto err;
        }

        netos_pcapng_shb_t *shb = (netos_pcapng_shb_t *)ctx->mapped_memory;

        if (shb->byte_order_magic == NETOS_PCAPNG_ENDIAN_BE) {
            ctx->rec.big_endian = true;
            printf("big endian\n");
        } else if (shb->byte_order_magic == NETOS_PCAPNG_ENDIAN_LE) {
            ctx->rec.big_endian = false;
            printf("little endian\n");
        } else {
            goto err;
        }

        ctx->offset += sizeof(netos_pcapng_shb_t);

        printf("block_total_len %d\n", shb->block_total_len);
        printf("byte order magic %x\n", shb->byte_order_magic);

        netos_pcapng_parse_shb(ctx, shb);

        return ctx;
    }

err:
    if (ctx) {
        if (ctx->fd > 0) {
            close(ctx->fd);
        }
        free(ctx);
    }

    return NULL;
}

