#ifndef NETOS_PROTOCOLS_MACSEC_HDR_H
#define NETOS_PROTOCOLS_MACSEC_HDR_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "netos_status.h"

#define NETOS_MACSEC_SCI_LEN        8
#define NETOS_MACSEC_ICV_LEN        16
#define NETOS_MACSEC_MIN_HDR_LEN    8
#define NETOS_MACSEC_MAX_HDR_LEN    16
#define NETOS_MACSEC_AN_LEN         4

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
    uint8_t                 *data;
    uint16_t                hdr_len;
    uint8_t                 icv[NETOS_MACSEC_ICV_LEN];
} netos_macsec_hdr_t;

netos_status_t
netos_macsec_decode(netos_macsec_hdr_t *macsec_hdr,
                    pkt_buffer_t *pkt_buf);

netos_status_t
netos_macsec_encode(netos_macsec_hdr_t *macsec_hdr,
                    pkt_buffer_t *pkt_buf);

#define NETOS_MACSEC_SET_SCI(__macsec, __sci) do {\
    (__macsec).sci[0] = __sci[0];\
    (__macsec).sci[1] = __sci[1];\
    (__macsec).sci[2] = __sci[2];\
    (__macsec).sci[3] = __sci[3];\
    (__macsec).sci[4] = __sci[4];\
    (__macsec).sci[5] = __sci[5];\
    (__macsec).sci[6] = __sci[6];\
    (__macsec).sci[7] = __sci[7];\
} while (0)

#define NETOS_MACSEC_DEFAULTS(__macsec, __sl, __sci, __es, __sc, __scb, __e, __c, __an) do {\
    (__macsec).tci_an.v     = 0;\
    (__macsec).tci_an.es    = __es;\
    (__macsec).tci_an.sc    = __sc;\
    (__macsec).tci_an.scb   = __scb;\
    (__macsec).tci_an.e     = __e;\
    (__macsec).tci_an.c     = __c;\
    (__macsec).tci_an.an    = __an;\
    (__macsec).sl           = __sl;\
    NETOS_MACSEC_SET_SCI(__macsec, __sci);\
    (__macsec).pn           = 1;\
    (__macsec).ethertype    = 0x0800;\
    (__macsec).data_len     = 0;\
    (__macsec).data         = NULL;\
    (__macsec).hdr_len      = 0;\
    memset((__macsec).icv, 0, NETOS_MACSEC_ICV_LEN);\
} while (0)

#if defined(__cplusplus)
}
#endif

#endif
