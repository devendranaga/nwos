#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "netos_status.h"
#include "pcap_intf.h"

netos_pcap_context_t *netos_pcap_open_file_to_read(const char *filename)
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

netos_pcap_context_t *netos_pcap_open_file_to_write(const char *filename, uint32_t file_size)
{
    netos_pcap_context_t *ctx;

    ctx = calloc(1, sizeof(netos_pcap_context_t));
    if (!ctx) {
        return NULL;
    }

    ctx->fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (ctx->fd < 0) {
        goto err;
    }

    ctx->mapped_memory = mmap(NULL, file_size,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED,
                              ctx->fd,
                              0);
    if (ctx->mapped_memory == MAP_FAILED) {
        goto err;
    }

    ctx->file_size  = file_size;
    ctx->offset     = 0;
    ctx->glob_hdr   = (netos_pcap_global_header_t *)ctx->mapped_memory;

    ctx->glob_hdr->magic            = 0xa1b2c3d4;
    ctx->glob_hdr->version_major    = 2;
    ctx->glob_hdr->version_minor    = 4;
    ctx->glob_hdr->thiszone         = 0;
    ctx->glob_hdr->sigfigs          = 0;
    ctx->glob_hdr->snaplen          = 65535;
    ctx->glob_hdr->network          = 1;

    return ctx;

err:
    if (ctx) {
        if (ctx->fd > 0) {
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
    // current offset + the packet header is beyond the given file size.
    // i.e. EOF.
    if ((ctx->offset + sizeof(netos_pcap_packet_header_t)) >= ctx->file_size) {
        return NETOS_STATUS_PCAP_EOF;
    }

    *pkt_hdr = (netos_pcap_packet_header_t *)(ctx->mapped_memory + ctx->offset);
    ctx->offset += sizeof(netos_pcap_packet_header_t);

    // typecast the buffer to the mapped memory ..this pointer is read-only!
    *buf = (uint8_t *)(ctx->mapped_memory + ctx->offset);

    ctx->offset += (*pkt_hdr)->incl_len;

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_pcap_write_file_entry(netos_pcap_context_t *ctx,
                                           uint8_t *buf,
                                           uint32_t buf_len,
                                           uint32_t ts_sec,
                                           uint32_t ts_usec)
{
    netos_pcap_packet_header_t *pkt_hdr;

    if ((ctx->offset + buf_len) >= ctx->file_size) {
        return NETOS_STATUS_PCAP_WRITE_BUFFER_FULL;
    }

    pkt_hdr = (netos_pcap_packet_header_t *)(ctx->mapped_memory + ctx->offset);

    pkt_hdr->ts_sec = ts_sec;
    pkt_hdr->ts_usec = ts_usec;
    pkt_hdr->incl_len = buf_len;
    pkt_hdr->orig_len = buf_len;

    ctx->offset += sizeof(netos_pcap_packet_header_t);

    memcpy(ctx->mapped_memory + ctx->offset, buf, buf_len);
    ctx->offset += buf_len;

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

