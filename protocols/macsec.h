#ifndef NETOS_PROTOCOLS_MACSEC_H
#define NETOS_PROTOCOLS_MACSEC_H

#include "macsec_hdr.h"
#include "crypto_intf.h"

#define NETOS_MACSEC_CIPHER_AES_GCM_128     1
#define NETOS_MACSEC_CIPHER_AES_GCM_256     2
#define NETOS_MACSEC_CIPHER_AES_GCM_XPN_128 3
#define NETOS_MACSEC_CIPHER_AES_GCM_XPN_256 4

#define NETOS_MACSEC_TXSA_LEN 4
#define NETOS_MACSEC_RXSA_LEN 4

#define NETOS_MACSEC_VALIDATION_MODE_CHECK 2
#define NETOS_MACSEC_VALIDATION_MODE_STRICT 3

typedef struct netos_macsec_txsa {
    bool                valid;
    uint8_t             an;
    uint64_t            pn;
    netos_crypto_key_t  sak;
} netos_macsec_txsa_t;

typedef struct netos_macsec_txsc {
    uint8_t             cipher_suite;
    uint8_t             current_an;
    netos_macsec_txsa_t txsa[NETOS_MACSEC_TXSA_LEN];
} netos_macsec_txsc_t;

typedef struct netos_macsec_rxsa {
    bool                valid;
    uint8_t             an;
    uint64_t            pn;
    netos_crypto_key_t  sak;
}
typedef struct netos_macsec_rxsc {
    uint8_t     cipher_suite;
    uint8_t     current_an;
    bool        replay_protect_en;
    uint32_t    replay_duration;
    bool        validate_frames;
    uint32_t    validation_mode;
} netos_macsec_rxsc_t;

typedef struct netos_macsec_secy {
    uint8_t             sci[NETOS_MACSEC_SCI_LEN];
    netos_macsec_txsc_t txsc;
    netos_macsec_rxsc_t rxsc;
} netos_macsec_secy_t;

typedef struct netos_macsec_protocol {

} netos_macsec_protocol_t;

#endif

