#ifndef NETOS_PROTOCOLS_MACSEC_H
#define NETOS_PROTOCOLS_MACSEC_H

#include "macsec_hdr.h"

#define NETOS_MACSEC_CIPHER_AES_GCM_128     1
#define NETOS_MACSEC_CIPHER_AES_GCM_256     2
#define NETOS_MACSEC_CIPHER_AES_GCM_XPN_128 3
#define NETOS_MACSEC_CIPHER_AES_GCM_XPN_256 4

typedef struct netos_macsec_txsc {
    uint8_t cipher_suite;
    uint8_t current_an;
} netos_macsec_txsc_t;

typedef struct netos_macsec_secy {
    uint8_t sci[NETOS_MACSEC_SCI_LEN];
} netos_macsec_secy_t;

typedef struct netos_macsec_protocol {

} netos_macsec_protocol_t;

#endif

