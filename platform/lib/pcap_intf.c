#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "netos_status.h"
#include "pcap_intf.h"

netos_pcap_context_t *netos_pcap_read_file(const char *filename)
{
    netos_pcap_context_t *ctx;
    struct stat st;
    int ret;

    ctx = calloc(1, sizeof(netos_pcap_context_t));
    if (!ctx) {
        return NULL;
    }

    ret = stat(filename, &st);
    if (ret != 0) {
        goto err;
    }

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
        goto err;
    }

    ctx->file_size = st.st_size;
    ctx->offset = 0;
    ctx->glob_hdr = (netos_pcap_global_header_t *)(ctx->mapped_memory);

    if ((ctx->glob_hdr->magic != NETOS_PCAP_MAGIC_NUMBER_BE) &&
        (ctx->glob_hdr->magic != NETOS_PCAP_MAGIC_NUMBER_LE)) {
        goto err;
    }

    ctx->offset += sizeof(netos_pcap_global_header_t);

    return ctx;

err:
    if (ctx) {
        if (ctx->mapped_memory != MAP_FAILED) {
            munmap(ctx->mapped_memory, ctx->file_size);
        }
        if (ctx->fd >= 0) {
            close(ctx->fd);
        }
        free(ctx);
    }

    return NULL;
}

netos_status_t netos_pcap_read_file_entry(netos_pcap_context_t *ctx,
                                          netos_pcap_packet_header_t **pkt_hdr,
                                          uint8_t **buf)
{
    if ((ctx->offset + sizeof(netos_pcap_packet_header_t)) >= ctx->file_size) {
        return NETOS_STATUS_PCAP_EOF;
    }

    *pkt_hdr = (netos_pcap_packet_header_t *)(ctx->mapped_memory + ctx->offset);
    ctx->offset += sizeof(netos_pcap_packet_header_t);

    *buf = (uint8_t *)(ctx->mapped_memory + ctx->offset);

    ctx->offset += (*pkt_hdr)->incl_len;

    return NETOS_STATUS_SUCCESS;
}

void netos_pcap_close_file(netos_pcap_context_t *ctx)
{
    if (ctx) {
        if (ctx->mapped_memory != MAP_FAILED) {
            munmap(ctx->mapped_memory, ctx->file_size);
        }
        if (ctx->fd >= 0) {
            close(ctx->fd);
        }
        free(ctx);
    }
}

