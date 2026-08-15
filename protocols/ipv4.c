#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include "netos_status.h"
#include "netos_config.h"
#include "packet_parser.h"
#include "protocols.h"
#include "icmp.h"
#include "ipv4.h"
#include "netos_log.h"

static struct {
    bool            valid;
    int             protocol;
    const char      *name;
    void            *protocol_ctx;

    void            *(*init)(netos_config_t *config);

    void            (*rx)(void *ctx,
                          netos_packet_parser_t *parsed_data,
                          pkt_buffer_t *pkt_buf);

    void            (*tx)(void *ctx,
                          pkt_buffer_t *pkt_buf);

    void            (*deinit)(void *ctx);
} protocol_table[255] = {
    {
        false,
        0,
        "none",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    },
    {
        true,
        NETOS_PROTOCOL_ICMP,
        "ICMP",
        NULL,
        netos_icmp_init,
        netos_icmp_rx,
        netos_icmp_tx,
        netos_icmp_deinit
    }
};

netos_status_t netos_ipv4_initialize(netos_config_t *config)
{
    uint32_t i;

    for (i = 0; i < sizeof(protocol_table) / sizeof(protocol_table[0]); i ++) {
        if (protocol_table[i].valid &&
            protocol_table[i].init) {
            protocol_table[i].protocol_ctx = protocol_table[i].init(config);
            if (!protocol_table[i].protocol_ctx) {
                netos_log_error("Failed to initialize protocol <%s>\n",
                                protocol_table[i].name);
                return NETOS_STATUS_PROTOCOL_INIT_FAILURE;
            }
            netos_log_info("%s initialized\n", protocol_table[i].name);
        }
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_ipv4_rx_process(pkt_buffer_t *pkt_buf,
                                     netos_packet_parser_t *pkt_parser)
{
    uint8_t protocol = pkt_parser->protocol;

    if (protocol_table[protocol].rx) {
        protocol_table[protocol].rx(protocol_table[protocol].protocol_ctx,
                                    pkt_parser,
                                    pkt_buf);
    }
    return NETOS_STATUS_SUCCESS;
}

