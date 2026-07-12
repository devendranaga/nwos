#include "udp_hdr.h"

netos_status_t netos_udp_decode(netos_udp_hdr_t *udp_hdr,
                                pkt_buffer_t *pkt_buf)
{
    if ((pkt_buf->offset + NETOS_UDP_HDR_LEN) > pkt_buf->rx_len) {
        return NETOS_STATUS_UDP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &udp_hdr->src_port);
    pkt_buffer_decode_2_bytes(pkt_buf, &udp_hdr->dst_port);
    pkt_buffer_decode_2_bytes(pkt_buf, &udp_hdr->length);
    if (udp_hdr->length == 0) {
        return NETOS_STATUS_UDP_MALFORMED_PKT;
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

