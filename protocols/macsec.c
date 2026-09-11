#include <string.h>
#include "netos_status.h"
#include "netos_config.h"
#include "pkt_buffer.h"
#include "gcd.h"
#include "macsec.h"

#define NETOS_MACSEC_SECY_MAX 128

static netos_macsec_protocol_t macsec_p;

static uint32_t netos_macsec_hash_fn(void *key)
{
    return 0;
}

static bool netos_macsec_cmp(void *key1, void *key2)
{
    return false;
}

netos_status_t netos_macsec_init(netos_config_t *config,
                                 netos_gcd_ctx_t *gcd_ctx)
{
    macsec_p.secy_table = netos_hash_table_init(NETOS_MACSEC_SECY_MAX,
                                                netos_macsec_hash_fn,
                                                netos_macsec_cmp);
    if (!macsec_p.secy_table) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    memset(&macsec_p.mib, 0, sizeof(netos_macsec_mib_t));

    return NETOS_STATUS_SUCCESS;
}

netos_macsec_secy_t *netos_macsec_create_txsc(uint8_t *sci, uint8_t cipher_suite)
{
    netos_macsec_secy_t *secy;

    secy = calloc(1, sizeof(netos_macsec_secy_t));
    if (!secy) {
        return NULL;
    }

    secy->secy_type = NETOS_MACSEC_SECY_TX_SC;

    secy->txsc = calloc(1, sizeof(netos_macsec_txsc_t));
    if (!secy->txsc) {
        goto err;
    }

    memcpy(secy->txsc->sci, sci, NETOS_MACSEC_SCI_LEN);
    secy->txsc->cipher_suite = cipher_suite;
    secy->txsc->current_an = 255;

    netos_hash_item_add(macsec_p.secy_table, sci, secy);

    return secy;

err:
    if (secy) {
        if (secy->txsc) {
            free(secy->txsc);
        }
        free(secy);
    }

    return NULL;
}

netos_macsec_secy_t *netos_macsec_create_rxsc(netos_macsec_rxsc_config_t *rxsc_config)
{
    netos_macsec_secy_t *secy;

    secy = calloc(1, sizeof(netos_macsec_secy_t));
    if (!secy) {
        return NULL;
    }

    secy->secy_type = NETOS_MACSEC_SECY_RX_SC;
    secy->rxsc = calloc(1, sizeof(netos_macsec_rxsc_t));
    if (!secy->rxsc) {
        goto err;
    }

    secy->rxsc->current_an = 255;
    secy->rxsc->rxsc_config = *rxsc_config;

    netos_hash_item_add(macsec_p.secy_table, rxsc_config->sci, secy);

    return secy;

err:
    if (secy) {
        if (secy->rxsc) {
            free(secy->rxsc);
        }
        free(secy);
    }

    return NULL;
}

netos_status_t netos_macsec_create_txsa(netos_macsec_secy_t *secy, uint8_t an, uint64_t pn, netos_crypto_key_t *sak)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    secy->txsc->txsa[an].valid = true;
    secy->txsc->txsa[an].an = an;
    secy->txsc->txsa[an].pn = pn;
    secy->txsc->txsa[an].sak = *sak;

    secy->txsc->txsa[an].crypto_ctx = netos_crypto_ctx_initialize();
    if (!secy->txsc->txsa[an].crypto_ctx) {
        return NETOS_STATUS_CRYPTO_CTX_INIT_FAILURE;
    }

    secy->txsc->txsa[an].gcm_ctx = netos_crypto_init_gcm(secy->txsc->txsa[an].crypto_ctx);
    if (!secy->txsc->txsa[an].gcm_ctx) {
        ret = NETOS_STATUS_CRYPTO_GCM_INIT_FAILURE;
        goto err;
    }

    return ret;

err:
    if (secy->txsc->txsa[an].crypto_ctx) {
        if (secy->txsc->txsa[an].gcm_ctx) {
            netos_crypto_deinit_gcm(secy->txsc->txsa[an].crypto_ctx,
                                    secy->txsc->txsa[an].gcm_ctx);
        }
    }
    return ret;
}

netos_status_t netos_macsec_create_rxsa(netos_macsec_secy_t *secy, uint8_t an, uint64_t pn, netos_crypto_key_t *sak)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    secy->rxsc->rxsa[an].valid = true;
    secy->rxsc->rxsa[an].an = an;
    secy->rxsc->rxsa[an].pn = pn;
    secy->rxsc->rxsa[an].sak = *sak;

    secy->rxsc->rxsa[an].crypto_ctx = netos_crypto_ctx_initialize();
    if (!secy->rxsc->rxsa[an].crypto_ctx) {
        return NETOS_STATUS_CRYPTO_CTX_INIT_FAILURE;
    }

    secy->rxsc->rxsa[an].gcm_ctx = netos_crypto_init_gcm(secy->rxsc->rxsa[an].crypto_ctx);
    if (!secy->rxsc->rxsa[an].gcm_ctx) {
        ret = NETOS_STATUS_CRYPTO_GCM_INIT_FAILURE;
        goto err;
    }

    return ret;

err:
    if (secy->rxsc->rxsa[an].crypto_ctx) {
        if (secy->rxsc->rxsa[an].gcm_ctx) {
            netos_crypto_deinit_gcm(secy->rxsc->rxsa[an].crypto_ctx,
                                    secy->rxsc->rxsa[an].gcm_ctx);
        }
    }
    return ret;
}

netos_status_t netos_macsec_encode_frame(netos_macsec_secy_t *secy, pkt_buffer_t *pkt_buf, uint32_t buf_len)
{
    return NETOS_STATUS_SUCCESS;
}

