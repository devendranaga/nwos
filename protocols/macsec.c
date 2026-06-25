#include <stdint.h>

#include "pkt_buffer.h"
#include "macsec_hdr.h"

netos_status_t netos_macsec_decode(netos_macsec_hdr_t *macsec_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if ((pkt_buf->offset + NETOS_MACSEC_MIN_HDR_LEN) > pkt_buf->rx_len) {
        return NETOS_STATUS_MACSEC_MALFORMED_PKT;
    }

    macsec_hdr->tci_an.v = !!(pkt_buf->buffer[pkt_buf->offset] & 0x80);
    macsec_hdr->tci_an.es = !!(pkt_buf->buffer[pkt_buf->offset] & 0x40);
    macsec_hdr->tci_an.sc = !!(pkt_buf->buffer[pkt_buf->offset] & 0x20);
    macsec_hdr->tci_an.scb = !!(pkt_buf->buffer[pkt_buf->offset] & 0x10);
    macsec_hdr->tci_an.e = !!(pkt_buf->buffer[pkt_buf->offset] & 0x08);
    macsec_hdr->tci_an.c = !!(pkt_buf->buffer[pkt_buf->offset] & 0x04);
    macsec_hdr->tci_an.an = (pkt_buf->buffer[pkt_buf->offset] & 0x03);

    pkt_buf->offset ++;

    pkt_buffer_decode_byte(pkt_buf, &macsec_hdr->sl);

    if (macsec_hdr->tci_an.sc) {
        pkt_buffer_decode_bytes(pkt_buf, macsec_hdr->sci, NETOS_MACSEC_SCI_LEN);
    }

    pkt_buffer_decode_4_bytes(pkt_buf, &macsec_hdr->pn);
    macsec_hdr->data_len = (pkt_buf->rx_len - pkt_buf->offset) - NETOS_MACSEC_ICV_LEN;

    // E=1 but C can never be 0 if E=1.
    if (macsec_hdr->tci_an.e && (macsec_hdr->tci_an.c == 0)) {
        return NETOS_STATUS_MACSEC_INVAL_E_1_C_0;
    }

    if ((macsec_hdr->tci_an.e == 0) && (macsec_hdr->tci_an.c == 1)) {
        pkt_buffer_decode_2_bytes(pkt_buf, &macsec_hdr->ethertype);
    }

    uint16_t icv_offset = pkt_buf->rx_len - NETOS_MACSEC_ICV_LEN;
    pkt_buf->rx_len -= NETOS_MACSEC_ICV_LEN;
    memcpy(macsec_hdr->icv, &pkt_buf->buffer[icv_offset], NETOS_MACSEC_ICV_LEN);

    return ret;
}
