#include <stdint.h>
#include <stdlib.h>
#include "netos_status.h"
#include "protocol_const.h"
#include "pkt_buffer.h"
#include "eth.h"
#include "event_info.h"
#include "netos_log.h"

netos_status_t netos_eth_decode(netos_eth_hdr_t *eh,
                                pkt_buffer_t *pkt_buf)
{
    // drop and write to event log
    if (!pkt_buffer_rx_frame_in_range(pkt_buf, NETOS_ETH_HDR_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ETH_SHORT_HDR);
        return NETOS_STATUS_ETH_MALFORMED_PKT;
    }

    pkt_buffer_decode_bytes(pkt_buf, eh->dst, NETOS_MACADDR_LEN);
    pkt_buffer_decode_bytes(pkt_buf, eh->src, NETOS_MACADDR_LEN);
    pkt_buffer_decode_2_bytes(pkt_buf, &eh->ethertype);

    return NETOS_STATUS_SUCCESS;
}

void netos_eth_print(netos_eth_hdr_t *eh)
{
    netos_log_debug("Eth:\n");
    netos_log_debug("\t DA: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            eh->dst[0], eh->dst[1], eh->dst[2],
                            eh->dst[3], eh->dst[4], eh->dst[5]);
    netos_log_debug("\t SA: %02x:%02x:%02x:%02x:%02x:%02x\n",
                            eh->src[0], eh->src[1], eh->src[2],
                            eh->src[3], eh->src[4], eh->src[5]);
    netos_log_debug("\t ethertype: 0x%04x\n", eh->ethertype);
}


