#include <stdint.h>
#include <stdlib.h>
#include "netos_status.h"
#include "protocol_const.h"
#include "pkt_buffer.h"
#include "eth.h"

netos_status_t netos_eth_decode(netos_eth_hdr_t *eh,
                                pkt_buffer_t *pkt_buf)
{
    if (!pkt_buffer_rx_frame_in_range(pkt_buf, NETOS_ETH_HDR_LEN)) {
        return NETOS_STATUS_ETH_MALFORMED_PKT;
    }

    pkt_buffer_decode_bytes(pkt_buf, eh->dst, NETOS_MACADDR_LEN);
    pkt_buffer_decode_bytes(pkt_buf, eh->src, NETOS_MACADDR_LEN);
    pkt_buffer_decode_2_bytes(pkt_buf, &eh->ethertype);

    return NETOS_STATUS_SUCCESS;
}


