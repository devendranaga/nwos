#include "vlan.h"
#include "netos_log.h"

netos_status_t netos_vlan_decode(netos_vlan_hdr_t *vlan_hdr,
                                 pkt_buffer_t *pkt_buf)
{
    if (pkt_buf->rx_len < (pkt_buf->offset + NETOS_VLAN_HDR_LEN)) {
        return NETOS_STATUS_VLAN_MALFORMED_PKT;
    }

    vlan_hdr->pcp = (pkt_buf->buffer[pkt_buf->offset] & 0xE0) >> 5;
    vlan_hdr->dei = (pkt_buf->buffer[pkt_buf->offset] & 0x10) >> 4;
    vlan_hdr->vlan_id = (((pkt_buf->buffer[pkt_buf->offset] & 0x0F) << 8) |
                         (pkt_buf->buffer[pkt_buf->offset + 1]));
    pkt_buf->offset += 2;

    pkt_buffer_decode_2_bytes(pkt_buf, &vlan_hdr->ethertype);

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_vlan_encode(const netos_vlan_hdr_t *vlan_hdr,
                                 pkt_buffer_t *pkt_buf)
{
    pkt_buf->buffer[pkt_buf->offset] = (vlan_hdr->pcp << 5);
    pkt_buf->buffer[pkt_buf->offset] |= (vlan_hdr->dei << 4);
    pkt_buf->buffer[pkt_buf->offset] |= ((vlan_hdr->vlan_id & 0x0F00) >> 8);
    pkt_buf->buffer[pkt_buf->offset + 1] = (vlan_hdr->vlan_id & 0x00FF);

    pkt_buf->offset += 2;

    pkt_buffer_encode_2_bytes(pkt_buf, vlan_hdr->ethertype);

    return NETOS_STATUS_SUCCESS;
}

void netos_vlan_print(netos_vlan_hdr_t *vlan_hdr)
{
    netos_log_debug("VLAN:\n");
    netos_log_debug("\t pcp: %d\n", vlan_hdr->pcp);
    netos_log_debug("\t dei: %d\n", vlan_hdr->dei);
    netos_log_debug("\t vlan_id: %d\n", vlan_hdr->vlan_id);
    netos_log_debug("\t ethertype: 0x%04x\n", vlan_hdr->ethertype);
}

