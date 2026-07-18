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
#include "netos_log.h"

// defines endian
#define NETOS_PCAPNG_ENDIAN_BE 0x4d3c2b1a
#define NETOS_PCAPNG_ENDIAN_LE 0x1a2b3c4d

// defines list of packet blocks
#define NETOS_PCAPNG_IDB 1
#define NETOS_PCAPNG_SPB 3
#define NETOS_PCAPNG_ISB 5
#define NETOS_PCAPNG_EPB 6

// defines an SHB block typecasted to the mapped memory
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

static inline uint16_t netos_pcapng_get_u16(netos_pcapng_ctx_t *ctx)
{
    uint16_t val = 0;
    uint8_t *pkt = ctx->mapped_memory;

    if (ctx->rec.big_endian) {
        val = (pkt[ctx->offset] << 8) | (pkt[ctx->offset + 1]);
    } else {
        val = (pkt[ctx->offset + 1] << 8) | (pkt[ctx->offset]);
    }

    ctx->offset += 2;

    return val;
}

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

    ctx->offset += 4;

    return val;
}

static inline uint32_t netos_pcapng_get_len_pad(uint32_t len)
{
    uint32_t len_pad = 0;

    if (len % 4 != 0) {
        len_pad = (len + 3) & ~3;
    }

    return len_pad;
}

static netos_status_t netos_pcapng_parse_shb(netos_pcapng_ctx_t *ctx,
                                             netos_pcapng_shb_t *shb,
                                             bool *no_options)
{
    uint32_t val_32;

    *no_options = false;

    val_32 = netos_pcapng_get_u32(ctx);
    if (val_32 != shb->block_total_len) {
        // may be options
    } else {
        // no options
        *no_options = true;
        return NETOS_STATUS_SUCCESS;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_pcapng_parse_idb(netos_pcapng_ctx_t *ctx,
                                             uint16_t block_total_len)
{
    uint32_t block_len;

    ctx->rec.idb.link_type = netos_pcapng_get_u16(ctx);
    ctx->offset += 2; // reserved bytes

    ctx->rec.idb.snaplen = netos_pcapng_get_u32(ctx);
    block_len = netos_pcapng_get_u32(ctx);

    if (block_len == block_total_len) {
        return NETOS_STATUS_SUCCESS;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_pcapng_parse_epb(netos_pcapng_ctx_t *ctx,
                                             uint16_t block_total_len,
                                             bool *no_options)
{
    uint32_t block_len;

    *no_options = false;

    ctx->rec.epb.intf_id        = netos_pcapng_get_u32(ctx);
    ctx->rec.epb.ts_high        = netos_pcapng_get_u32(ctx);
    ctx->rec.epb.ts_low         = netos_pcapng_get_u32(ctx);
    ctx->rec.epb.captured_len   = netos_pcapng_get_u32(ctx);
    ctx->rec.epb.original_len   = netos_pcapng_get_u32(ctx);
    ctx->rec.epb.pkt_data       = &ctx->mapped_memory[ctx->offset];

    netos_pcapng_frame_t frame = {
        .original_len   = ctx->rec.epb.original_len,
        .captured_len   = ctx->rec.epb.captured_len,
        .pkt            = ctx->rec.epb.pkt_data,
    };
    ctx->offset += netos_pcapng_get_len_pad(ctx->rec.epb.captured_len);

    block_len = netos_pcapng_get_u32(ctx);
    if (block_len != block_total_len) {
        // options
    } else if (block_len == block_total_len) {
        *no_options = true;
    }

    ctx->parse_cb(ctx->user_ctx, &frame);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_pcapng_parse_blocks(netos_pcapng_ctx_t *ctx)
{
    uint32_t block_type;
    uint32_t block_total_len;
    bool has_options;
    netos_status_t ret;

    do {
        block_type = netos_pcapng_get_u32(ctx);
        block_total_len = netos_pcapng_get_u32(ctx);

        switch (block_type) {
            case 0: {
                return NETOS_STATUS_SUCCESS;
            } break;
            case NETOS_PCAPNG_IDB: {
                ret = netos_pcapng_parse_idb(ctx, block_total_len);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return NETOS_STATUS_PCAPNG_INVAL_PKT_BLOCK;
                }
            } break;
            case NETOS_PCAPNG_SPB:
            break;
            case NETOS_PCAPNG_EPB: {
                has_options = false;

                ret = netos_pcapng_parse_epb(ctx, block_total_len, &has_options);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return NETOS_STATUS_PCAPNG_INVAL_PKT_BLOCK;
                }
            } break;
            case NETOS_PCAPNG_ISB:
            break;
            default:
                netos_log_error("%s: Unknown block_type %d and block_total_len %d\n",
                                __func__, block_type, block_total_len);
        }
    } while (1);

    return NETOS_STATUS_SUCCESS;
}

netos_pcapng_ctx_t *netos_pcapng_ctx_parse(netos_pcapng_op_t op,
                                           const char *filename,
                                           void *user_ctx,
                                           netos_pcapng_parse_cb parse_cb)
{
    netos_pcapng_ctx_t *ctx;
    struct stat st;
    netos_status_t res;
    int ret;

    ret = stat(filename, &st);
    if (ret != 0) {
        return NULL;
    }

    ctx = calloc(1, sizeof(netos_pcapng_ctx_t));
    if (!ctx) {
        return NULL;
    }

    ctx->user_ctx = user_ctx;
    ctx->parse_cb = parse_cb;

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
        } else if (shb->byte_order_magic == NETOS_PCAPNG_ENDIAN_LE) {
            ctx->rec.big_endian = false;
        } else {
            goto err;
        }

        ctx->offset += sizeof(netos_pcapng_shb_t);

        bool no_options = false;
        res = netos_pcapng_parse_shb(ctx, shb, &no_options);
        if (res != NETOS_STATUS_SUCCESS) {
            goto err;
        }

        res = netos_pcapng_parse_blocks(ctx);
        if (res != NETOS_STATUS_SUCCESS) {
            goto err;
        }

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

