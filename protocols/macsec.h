#ifndef NETOS_PROTOCOLS_MACSEC_H
#define NETOS_PROTOCOLS_MACSEC_H

#include "macsec_hdr.h"

typedef struct netos_macsec_txsc {

}
typedef struct netos_macsec_secy {
    uint8_t sci[NETOS_MACSEC_SCI_LEN];
} netos_macsec_secy_t;

typedef struct netos_macsec_protocol {

} netos_macsec_protocol_t;

#endif

