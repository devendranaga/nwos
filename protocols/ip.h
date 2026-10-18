#ifndef NETOS_IP_H
#define NETOS_IP_H

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief - Initialize IP interface.
 *
 * @param [in] config - netos config.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_ip_initialize(netos_config_t *config);

/**
 * @brief - Process IPv4 frames.
 *
 * @param [in] pkt_buf - received packet buffer.
 * @param [in] pkt_parser - parsed packet.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_ipv4_rx_process(pkt_buffer_t *pkt_buf,
                                     netos_packet_parser_t *pkt_parser);

/**
 * @brief - Process IPv6 frames.
 *
 * @param [in] pkt_buf - received packet buffer.
 * @param [in] pkt_parser - parsed packet.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_ipv6_rx_process(pkt_buffer_t *pkt_buf,
                                     netos_packet_parser_t *pkt_parser);

/**
 * @brief - Deinitialize the IP interface.
 */
void netos_ip_deinitialize(void);

#if defined(__cplusplus)
}
#endif

#endif

