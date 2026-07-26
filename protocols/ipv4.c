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
    void            *potocol_ctx;
    void            *cb_data;

    void            *(*init)(network_config_t *config);

    netos_status_t  (*rx)(void *ctx,
                          netos_packet_parser_t *parsed_data,
                          pkt_buffer_t *pkt_buf,
                          void *cb_data);

    netos_status_t  (*tx)(void *ctx,
                          pkt_buffer_t *pkt_buf);

    void            (*deinit)(void *ctx);
} protocol_table[255] = {
    {
        true,
        NETOS_PROTOCOL_ICMP,
        "ICMP",
        NULL,
        NULL,
        netos_icmp_init,
        netos_icmp_rx,
        netos_icmp_tx,
        netos_icmp_deinit
    }
};

netos_status_t netos_ipv4_initialize(network_config_t *config)
{
    uint32_t i;

    for (i = 0; i < sizeof(protocol_table) / sizeof(protocol_table[0]); i ++) {
        if (protocol_table[i].valid &&
            protocol_table[i].init) {
            protocol_table[i].potocol_ctx = protocol_table[i].init(config);
            if (!protocol_table[i].potocol_ctx) {
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
    return NETOS_STATUS_SUCCESS;
}

