#include <stdint.h>
#include "netos_status.h"
#include "event_info.h"
#include "udp_hdr.h"

netos_status_t netos_udp_decode(netos_udp_hdr_t *udp_hdr,
                                pkt_buffer_t *pkt_buf)
{
    // short header length
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_UDP_HDR_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_UDP_SHORT_HDR_LEN);
        return NETOS_STATUS_UDP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &udp_hdr->src_port);
    pkt_buffer_decode_2_bytes(pkt_buf, &udp_hdr->dst_port);
    pkt_buffer_decode_2_bytes(pkt_buf, &udp_hdr->length);

    // invalid length
    if (udp_hdr->length == 0) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_UDP_LEN_ZERO);
        return NETOS_STATUS_ZERO_UDP_LENGTH;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &udp_hdr->checksum);

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_udp_encode(netos_udp_hdr_t *udp_hdr,
                                pkt_buffer_t *pkt_buf)
{
    pkt_buffer_encode_2_bytes(pkt_buf, udp_hdr->src_port);
    pkt_buffer_encode_2_bytes(pkt_buf, udp_hdr->dst_port);
    pkt_buffer_encode_2_bytes(pkt_buf, udp_hdr->length);
    pkt_buffer_encode_2_bytes(pkt_buf, udp_hdr->checksum);

    return NETOS_STATUS_SUCCESS;
}

