#ifndef NETOS_RAW_SOCKET_H
#define NETOS_RAW_SOCKET_H

#include "protocol_const.h"
#include "netos_status.h"

/**
 * @brief - Defines Raw socket context.
 */
typedef struct {
    int         fd;
    char        *ifname;
    uint8_t     mac[NETOS_MACADDR_LEN];
    uint32_t    ipaddr;
    int         ifindex;
    void        *egress_ctrl;
} netos_raw_socket_ctx_t;

/**
 * @brief - initializes raw socket.
 *
 * @param [in] ifname - interface name.
 *
 * @return raw socket context on sucess and NULL pointer on failure.
 */
netos_raw_socket_ctx_t *netos_raw_socket_init(const char *ifname);

/**
 * @brief - deinitialize raw socket.
 *
 * @param [in] raw - raw socket context.
 */
void netos_raw_socket_deinit(netos_raw_socket_ctx_t *raw);

/**
 * @brief - receive a packet in the data pointer.
 *
 * @param [in] raw - raw socket context.
 * @param [out] data - rx buffer.
 * @param [in] data_len - length of the rx buffer.
 *
 * @return rx length on success <=0 on failure.
 */
int netos_raw_socket_rx(netos_raw_socket_ctx_t *raw, uint8_t *data, uint32_t data_len);

/**
 * @brief - transmit a packet from the data pointer.
 *
 * @param [in] raw - raw socket context.
 * @param [in] data - tx buffer.
 * @param [in] data_len - length of the tx buffer.
 *
 * @return tx length on success <=0 on failure.
 */
int netos_raw_socket_tx(netos_raw_socket_ctx_t *raw, uint8_t *data, uint32_t data_len);

int netos_raw_socket_rx_ethertype(netos_raw_socket_ctx_t *raw,
                                  uint8_t *data,
                                  uint32_t data_len,
                                  uint16_t ethertype);
#endif

