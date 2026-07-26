#ifndef NETOS_PROTOCOLS_MACSEC_H
#define NETOS_PROTOCOLS_MACSEC_H

#include "netos_status.h"
#include "pkt_buffer.h"
#include "macsec_hdr.h"
#include "crypto_intf.h"
#include "hash_tables.h"
#include "crypto_ctx.h"

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
    netos_crypto_ctx_t  *crypto_ctx;
    void                *gcm_ctx;
} netos_macsec_txsa_t;

typedef struct netos_macsec_txsc {
    uint8_t             sci[NETOS_MACSEC_SCI_LEN];
    uint8_t             cipher_suite;
    uint8_t             current_an;
    netos_macsec_txsa_t txsa[NETOS_MACSEC_TXSA_LEN];
} netos_macsec_txsc_t;

typedef struct netos_macsec_rxsa {
    bool                valid;
    uint8_t             an;
    uint64_t            pn;
    netos_crypto_key_t  sak;
    netos_crypto_ctx_t  *crypto_ctx;
    void                *gcm_ctx;
} netos_macsec_rxsa_t;

typedef struct netos_macsec_rxsc {
    uint8_t             sci[NETOS_MACSEC_SCI_LEN];
    uint8_t             cipher_suite;
    uint8_t             current_an;
    bool                replay_protect_en;
    uint32_t            replay_duration;
    bool                validate_frames;
    uint32_t            validation_mode;
    netos_macsec_rxsa_t rxsa[NETOS_MACSEC_RXSA_LEN];
} netos_macsec_rxsc_t;

typedef enum macsec_secy_type {
    NETOS_MACSEC_SECY_TX_SC,
    NETOS_MACSEC_SECY_RX_SC,
} macsec_secy_type_t;

/**
 * At any point only one is valid below.
 *
 * For a single master and 7 peers, there is only one valid txsc
 * pointer and many or 7 valid rxsc pointers.
 */
typedef struct netos_macsec_secy {
    macsec_secy_type_t  secy_type;
    netos_macsec_txsc_t *txsc;
    netos_macsec_rxsc_t *rxsc;
} netos_macsec_secy_t;

typedef struct netos_macsec_mib {
    uint64_t in_rx_ok;
    uint64_t in_rx_no_sa_err;
    uint64_t in_octets;
    uint64_t out_tx_ok;
    uint64_t out_octets;
} netos_macsec_mib_t;

typedef struct netos_macsec_protocol {
    netos_hash_table_t *secy_table;
    netos_macsec_mib_t mib;
} netos_macsec_protocol_t;

#endif

