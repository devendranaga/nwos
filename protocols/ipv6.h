#ifndef NETOS_IPV6_H
#define NETOS_IPV6_H

typedef struct {

} netos_ipv6_protocol_t;

netos_status_t netos_ipv6_initialize(netos_config_t *config);

netos_status_t netos_ipv6_rx_process(pkt_buffer_t *pkt_buf,
                                     netos_packet_parser_t *pkt_parser);

#endif

