#include <stdint.h>
#include <stdio.h>
#include "pcapng_intf.h"

void packet_callback(void *ctx, netos_pcapng_frame_t *frame)
{
    static uint32_t count = 1;
    uint32_t i;

    fprintf(stderr, "frame[%d]: [%d] ", count ++, frame->captured_len);
    for (i = 0; i < frame->captured_len; i ++) {
        fprintf(stderr, "%02x", frame->pkt[i]);
    }
    fprintf(stderr, "\n");
}

int main(int argc, char **argv)
{
    char *filename = argv[1];
    netos_pcapng_ctx_t *pcapng;

    pcapng = netos_pcapng_ctx_parse(NETOS_PCAPNG_OP_READ, filename, NULL, packet_callback);
    if (!pcapng) {
        printf("failed to parse pcapng\n");
        return -1;
    }

    return 0;
}
