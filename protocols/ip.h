#ifndef NETOS_IP_H
#define NETOS_IP_H

typedef struct {

} netos_ipv4_protocol_t;

netos_status_t netos_ip_initialize(netos_config_t *config);

netos_status_t netos_ipv4_rx_process(pkt_buffer_t *pkt_buf,
                                     netos_packet_parser_t *pkt_parser);

netos_status_t netos_ipv6_rx_process(pkt_buffer_t *pkt_buf,
                                     netos_packet_parser_t *pkt_parser);

#endif

