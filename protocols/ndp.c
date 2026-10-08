#include <stdio.h>
#include "netos_status.h"
#include "ndp.h"
#include "packet_parser.h"
#include "netos_config.h"
#include "netos_log.h"

static uint32_t netos_ndp_hash_fn(void *key)
{
    return 0;
}

static bool netos_ndp_cmp_fn(void *key1, void *key2)
{
    return true;
}

static bool netos_ndp_del_fn(void *key, void *val)
{
    return true;
}

void *netos_ndp_init(netos_config_t *config)
{
    netos_ndp_ctx_t *ndp_ctx;

    ndp_ctx = calloc(1, sizeof(netos_ndp_ctx_t));
    if (!ndp_ctx) {
        NETOS_PANIC("NDP: Failed to allocate @ %s %u\n", __func__, __LINE__);
    }

    ndp_ctx->config = config;

    ndp_ctx->ndp_cache = netos_hash_table_init(NETOS_NDP_CACHE_MAX_LEN,
                                               netos_ndp_hash_fn,
                                               netos_ndp_cmp_fn);
    if (!ndp_ctx->ndp_cache) {
        netos_log_error("NDP: Failed to allocate cache\n");
        goto err;
    }

    netos_log_info("NDP initialized\n");

    return ndp_ctx;

err:
    if (ndp_ctx) {
        if (ndp_ctx->ndp_cache) {
            netos_hash_table_deinit(ndp_ctx->ndp_cache, netos_ndp_del_fn);
        }
        free(ndp_ctx);
    }

    return NULL;
}

void netos_ndp_rx(void *ctx,
                  netos_packet_parser_t *pkt_parser,
                  pkt_buffer_t *pkt_buf)
{
}

void netos_ndp_deinit(void *ctx)
{
    netos_ndp_ctx_t *ndp_ctx = ctx;

    if (ndp_ctx) {
        if (ndp_ctx->ndp_cache) {
            netos_hash_table_deinit(ndp_ctx->ndp_cache, netos_ndp_del_fn);
        }
        free(ndp_ctx);
    }
}

