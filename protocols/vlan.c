#include "vlan.h"

netos_status_t netos_vlan_decode(netos_vlan_hdr_t *vlan_hdr,
                                 pkt_buffer_t *pkt_buf)
{
    if (pkt_buf->rx_len < (pkt_buf->offset + NETOS_VLAN_HDR_LEN)) {
        return NETOS_STATUS_VLAN_MALFORMED_PKT;
    }

    vlan_hdr->pcp = (pkt_buf->buffer[pkt_buf->offset] & 0xE0) >> 5;
    vlan_hdr->dei = (pkt_buf->buffer[pkt_buf->offset] & 0x10) >> 4;
    vlan_hdr->vlan_id = ((pkt_buf->buffer[pkt_buf->offset] << 8) |
                         (pkt_buf->buffer[pkt_buf->offset + 1]));
    pkt_buf->offset += 2;

    pkt_buffer_decode_2_bytes(pkt_buf, &vlan_hdr->ethertype);

    return NETOS_STATUS_SUCCESS;
}
