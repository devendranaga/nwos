#include <stdint.h>
#include <stdio.h>
#include "netos_status.h"
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

void dns_callback(void *ctx, netos_pcapng_dns_lookup_data_t *dns)
{
    fprintf(stderr, "dns->is_ipv4 : %d\n", dns->is_ipv4);
    fprintf(stderr, "dns->ipaddr: %s\n", dns->ipaddr_str);
}

int main(int argc, char **argv)
{
    netos_pcapng_parse_callbacks_t callbacks = {
        .parse_cb = packet_callback,
        .dns_cb = dns_callback,
    };
    char *filename = argv[1];
    netos_status_t ret;

    ret = netos_pcapng_ctx_parse(filename, NULL, &callbacks);
    if (ret != NETOS_STATUS_SUCCESS) {
        printf("failed to parse pcapng error: %x\n", ret);
        return -1;
    }

    return 0;
}
