#include <stdio.h>
#include <stdlib.h>
#include "netos_status.h"
#include "pcap_intf.h"

netos_pcap_context_t *netos_pcap_read_file(const char *filename)
{
    netos_pcap_context_t *ctx;

    ctx = calloc(1, sizeof(netos_pcap_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->fp = fopen(filename, "r");
    if (!ctx->fp) {
        goto err;
    }

    int len = fread(&ctx->glob_hdr, sizeof(netos_pcap_global_header_t), 1, ctx->fp);
    if (len != 1) {
        goto err;
    }

    if ((ctx->glob_hdr.magic != NETOS_PCAP_MAGIC_NUMBER_BE) &&
        (ctx->glob_hdr.magic != NETOS_PCAP_MAGIC_NUMBER_LE)) {
        goto err;
    }

    return ctx;

err:
    if (ctx) {
        if (ctx->fp) {
            fclose(ctx->fp);
        }
        free(ctx);
    }

    return NULL;
}

netos_status_t netos_pcap_read_file_entry(netos_pcap_context_t *ctx,
                                          netos_pcap_packet_header_t *pkt_hdr,
                                          uint8_t *buf)
{
    int len;

    len = fread(pkt_hdr, sizeof(netos_pcap_packet_header_t), 1, ctx->fp);
    if (len != 1) {
        if (feof(ctx->fp)) {
            return NETOS_STATUS_PCAP_EOF;
        }
        return NETOS_STATUS_PCAP_INVAL_PKT_HDR;
    }

    len = fread(buf, 1, pkt_hdr->incl_len, ctx->fp);
    if (len != (int)pkt_hdr->incl_len) {
        return NETOS_STATUS_PCAP_INVAL_PKT_HDR;
    }

    return NETOS_STATUS_SUCCESS;
}

void netos_pcap_close_file(netos_pcap_context_t *ctx)
{
    if (ctx) {
        if (ctx->fp) {
            fclose(ctx->fp);
        }
        free(ctx);
    }
}

