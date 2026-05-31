#ifndef NETOS_PROTOCOLS_MACSEC_H
#define NETOS_PROTOCOLS_MACSEC_H

#include "netos_status.h"

#define NETOS_MACSEC_SCI_LEN 8
#define NETOS_MACSEC_ICV_LEN 16
#define NETOS_MACSEC_MIN_HDR_LEN 8
#define NETOS_MACSEC_MAX_HDR_LEN 16

typedef struct {
    uint8_t v;
    uint8_t es;
    uint8_t sc;
    uint8_t scb;
    uint8_t e;
    uint8_t c;
    uint8_t an;
} netos_macsec_tci_an_t;

typedef struct netos_macsec_hdr {
    netos_macsec_tci_an_t   tci_an;
    uint8_t                 sl;
    uint8_t                 sci[NETOS_MACSEC_SCI_LEN];
    uint32_t                pn;
    uint16_t                ethertype;
    uint16_t                data_len;
    uint8_t                 icv[NETOS_MACSEC_ICV_LEN];
} netos_macsec_hdr_t;

netos_status_t netos_macsec_decode(netos_macsec_hdr_t *macsec_hdr, pkt_buffer_t *pkt_buf);

#endif
