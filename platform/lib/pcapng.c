#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

#define NETOS_IDB_OPT_IFNAME 2
#define NETOS_IDB_OPT_IFDESC 3
#define NETOS_IDB_OPT_TSRESOL 9
#define NETOS_IDB_OPT_IFFILTER 11
#define NETOS_IDB_OPT_OS 12
#define NETOS_IDB_OPT_FCS_LEN 13

#define NETOS_SHB_OPT_COMMENT   1
#define NETOS_SHB_OPT_HW        2
#define NETOS_SHB_OPT_OS        3
#define NETOS_SHB_OPT_APP       4

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
    } else {
        len_pad = len;
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
        uint16_t opt_type;
        uint16_t opt_len;

        ctx->offset -= 4;

        do {
            opt_type = netos_pcapng_get_u16(ctx);
            opt_len = netos_pcapng_get_u16(ctx);

            switch (opt_type) {
                case 0: {
                    if (opt_len == 0) {
                        val_32 = netos_pcapng_get_u32(ctx);
                        if (val_32 == shb->block_total_len) {
                            return NETOS_STATUS_SUCCESS;
                        }
                        return NETOS_STATUS_PCAPNG_INVAL_PKT_BLOCK;
                    }
                } break;
                case NETOS_SHB_OPT_COMMENT: {
                    if (ctx->rec.comment) {
                        free(ctx->rec.comment);
                    }

                    ctx->rec.comment = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!ctx->rec.comment) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(ctx->rec.comment, ctx->mapped_memory + ctx->offset, opt_len);
                    ctx->rec.comment[opt_len] = '\0';

                    printf("comment %s\n", ctx->rec.comment);
                } break;
                case NETOS_SHB_OPT_HW: {
                    ctx->rec.hw = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!ctx->rec.hw) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(ctx->rec.hw, ctx->mapped_memory + ctx->offset, opt_len);
                    ctx->rec.hw[opt_len] = '\0';

                    printf("hw %s\n", ctx->rec.hw);
                } break;
                case NETOS_SHB_OPT_OS: {
                    ctx->rec.os = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!ctx->rec.os) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(ctx->rec.os, ctx->mapped_memory + ctx->offset, opt_len);
                    ctx->rec.os[opt_len] = '\0';

                    printf("os %s\n", ctx->rec.os);
                } break;
                case NETOS_SHB_OPT_APP: {
                    ctx->rec.app = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!ctx->rec.app) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(ctx->rec.app, ctx->mapped_memory + ctx->offset, opt_len);
                    ctx->rec.app[opt_len] = '\0';

                    printf("app %s\n", ctx->rec.app);
                } break;
                default:
                    fprintf(stderr, "Invalid opt_type %04x opt_len %d\n", opt_type, opt_len);
                    return NETOS_STATUS_PCAPNG_INVAL_PKT_BLOCK;
                break;
            }

            ctx->offset += netos_pcapng_get_len_pad(opt_len);
        } while (1);

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
    } else {
        // contain options
        uint16_t opt_type;
        uint16_t opt_len;

        ctx->offset -= 4;
        do {
            opt_type = netos_pcapng_get_u16(ctx);
            opt_len = netos_pcapng_get_u16(ctx);

            printf("%s opt_type %04x opt_len %d\n", __func__, opt_type, opt_len);

            netos_pcapng_idb_opt_t *idb_opt = &ctx->rec.idb.idb_opt;

            switch (opt_type) {
                case 0: {
                    if (opt_len == 0) {
                        block_len = netos_pcapng_get_u32(ctx);
                        if (block_len != block_total_len) {
                            return NETOS_STATUS_PCAPNG_INVAL_PKT_BLOCK;
                        }

                        return NETOS_STATUS_SUCCESS;
                    }
                } break;
                case NETOS_IDB_OPT_IFNAME: {
                    idb_opt->ifname = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!idb_opt->ifname) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(idb_opt->ifname, ctx->mapped_memory + ctx->offset, opt_len);
                    idb_opt->ifname[opt_len] = '\0';

                    printf("ifname %s\n", idb_opt->ifname);
                } break;
                case NETOS_IDB_OPT_IFDESC: {
                    idb_opt->ifdesc = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!idb_opt->ifdesc) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(idb_opt->ifdesc, ctx->mapped_memory + ctx->offset, opt_len);
                    idb_opt->ifdesc[opt_len] = '\0';

                    printf("ifdesc %s\n", idb_opt->ifdesc);
                } break;
                case NETOS_IDB_OPT_TSRESOL: {
                    idb_opt->ts_resol = *(uint8_t *)(ctx->mapped_memory + ctx->offset);

                    printf("tsresol %d\n", idb_opt->ts_resol);
                } break;
                case NETOS_IDB_OPT_IFFILTER: {
                    idb_opt->iffilter = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!idb_opt->iffilter) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(idb_opt->iffilter, ctx->mapped_memory + ctx->offset, opt_len);
                    idb_opt->iffilter[opt_len] = '\0';

                    printf("iffilter %s %d\n", idb_opt->iffilter, opt_len);
                } break;
                case NETOS_IDB_OPT_OS: {
                    idb_opt->os = calloc(1, sizeof(char) * (opt_len + 1));
                    if (!idb_opt->os) {
                        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                    }

                    memcpy(idb_opt->os, ctx->mapped_memory + ctx->offset, opt_len);
                    idb_opt->os[opt_len] = '\0';

                    printf("---> opt_len %d\n", opt_len);
                    printf("os %s\n", idb_opt->os);
                } break;
                case NETOS_IDB_OPT_FCS_LEN: {
                    idb_opt->fcs_len = *(uint8_t *)(ctx->mapped_memory + ctx->offset);

                    printf("fcs len %d\n", idb_opt->fcs_len);
                } break;
                default:
                    netos_log_error("%s: %u: unknown opt_type %04x opt_len %d\n", __func__, __LINE__, opt_type, opt_len);
                    return NETOS_STATUS_PCAPNG_INVAL_PKT_BLOCK;
            }

            printf("offset before %d opt_len %d %d\n", ctx->offset, opt_len, netos_pcapng_get_len_pad(opt_len));
            ctx->offset += netos_pcapng_get_len_pad(opt_len);
        } while (1);
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
    ctx->rec.epb.pkt_data       = (uint8_t *)(ctx->mapped_memory + ctx->offset);

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
                netos_log_error("%s: Unknown block_type %08x and block_total_len %d\n",
                                __func__, block_type, block_total_len);
                return -1;
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
        if (ctx->rec.os) {
            free(ctx->rec.os);
        }
        if (ctx->fd > 0) {
            close(ctx->fd);
        }
        free(ctx);
    }

    return NULL;
}

