#ifndef NETOS_RAW_SOCKET_H
#define NETOS_RAW_SOCKET_H

#include "protocol_const.h"
#include "netos_status.h"

/**
 * @brief - Defines Raw socket context.
 */
typedef struct {
    // raw file descriptor of the underling interface
    int         fd;
    // interface this fd belongs
    char        *ifname;
    // mac address of the interface
    uint8_t     mac[NETOS_MACADDR_LEN];
    // ip address of this interface
    uint32_t    ipaddr;
    // interface index
    int         ifindex;
    // mtu size
    uint32_t    mtu;
    // egress controller pointer
    void        *egress_ctrl;
    // statistics pointer
    void        *stats_ctx;
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

/**
 * @brief - Receive frame with specific ethertype.
 *
 * @param [in] raw - raw socket context.
 * @param [inout] data - rx buffer.
 * @param [in] data_len - rx buffer length.
 * @param [in] ethertype - Ethertype to match in the rx frame.
 *
 * @return rx length on success, 0 if no frame matched, -1 on error.
 */
int netos_raw_socket_rx_ethertype(netos_raw_socket_ctx_t *raw,
                                  uint8_t *data,
                                  uint32_t data_len,
                                  uint16_t ethertype);
#endif

