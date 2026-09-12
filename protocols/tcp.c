#include "netos_status.h"
#include "netos_config.h"
#include "common.h"
#include "port_numbers.h"
#include "packet_parser.h"
#include "mqtt.h"
#include "tcp_hdr.h"
#include "tcp.h"
#include "netos_log.h"

static struct {
    bool        valid;
    uint16_t    dest_port;
    void        *protocol_ctx;
    void        *(*init)(netos_config_t *config);
    void        (*rx)(void *ctx,
                      netos_packet_parser_t *parsed_data,
                      pkt_buffer_t *pkt_buf);
    void        (*tx)(void *ctx,
                      pkt_buffer_t *pkt_buf);
    void        (*deinit)(void *ctx);
} application_callbacks[] = {
    {
        true,
        NETOS_PORT_NUM_MQTT,
        NULL,
        netos_mqtt_init,
        netos_mqtt_rx,
        netos_mqtt_tx,
        netos_mqtt_deinit
    }
};

void *netos_tcp_initialize(netos_config_t *config)
{
    netos_tcp_context_t *tcp_ctx;
    uint32_t i;

    tcp_ctx = calloc(1, sizeof(netos_tcp_context_t));
    if (!tcp_ctx) {
        return NULL;
    }

    for (i = 0; i < NETOS_SIZEOF_ARRAY(application_callbacks); i ++) {
        if (application_callbacks[i].valid &&
            application_callbacks[i].init) {
            application_callbacks[i].protocol_ctx =
                        application_callbacks[i].init(config);
        }
    }

    netos_log_info("TCP Initialized\n");

    return tcp_ctx;
}

void netos_tcp_rx_process(void *ctx,
                          netos_packet_parser_t *pkt_parser,
                          pkt_buffer_t *pkt_buf)
{
    uint32_t i;

    for (i = 0; i < NETOS_SIZEOF_ARRAY(application_callbacks); i ++) {
        if (application_callbacks[i].valid &&
            (pkt_parser->l4.tcp_hdr.dst_port ==
             application_callbacks[i].dest_port)) {
            application_callbacks[i].rx(
                                application_callbacks[i].protocol_ctx,
                                pkt_parser,
                                pkt_buf);
        }
    }
}

void netos_tcp_tx_process(void *ctx, pkt_buffer_t *pkt_buf)
{

}

void netos_tcp_deinit(void *ctx)
{

}

