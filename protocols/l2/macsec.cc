#include <iostream>
#include <functional>

#include "macsec.h"

namespace netos {

netos_status macsec_context::initialize(uint32_t n_secy, uint32_t n_rxsc)
{
    this->secy_list_ = new hash_table<uint8_t *, macsec_secy *>;
    if (!this->secy_list_) {
        return netos_status::NETOS_STATUS_ALLOC_FAILURE;
    }

    hash_fn<uint8_t *> macsec_hash_fn = std::bind(
                                            &macsec_context::hash_sci,
                                            this,
                                            std::placeholders::_1);
    find_fn<uint8_t *> macsec_find_fn = std::bind(
                                            &macsec_context::find_sci,
                                            this,
                                            std::placeholders::_1,
                                            std::placeholders::_2);
    del_fn<uint8_t *, macsec_secy *> macsec_del_fn = std::bind(
                                                        &macsec_context::del_sci,
                                                        this,
                                                        std::placeholders::_1,
                                                        std::placeholders::_2);
    /**
     * Initialize hash table with combined sci lenght for 1 txsc and n rxsc multiplied
     * by the number of secy.
     */
    this->secy_list_->initialize(n_secy * (n_rxsc + 1), // n secy x (n rxsc + 1 txsc)
                                 macsec_hash_fn,
                                 macsec_find_fn,
                                 macsec_del_fn,
                                 nullptr);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status macsec_context::create_secy(macsec_cipher_info cipher, uint8_t *sci)
{
    macsec_secy *secy = (macsec_secy *)calloc(1, sizeof(macsec_secy));
    if (!secy) {
        return netos_status::NETOS_STATUS_ALLOC_FAILURE;
    }

    secy->cipher = cipher;
    memcpy(secy->sci, sci, MACSEC_SCI_LEN);

    this->secy_list_->add(sci, secy);

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status macsec_context::create_txsc(uint8_t *sci, bool always_tx_sci)
{
    macsec_secy *secy = NULL;
    bool found;

    found = this->secy_list_->find(sci, &secy);
    if (!found) {
        return netos_status::NETOS_STATUS_MACSEC_SECY_NOT_FOUND;
    }

    memcpy(secy->txsc.sci, sci, MACSEC_SCI_LEN);
    secy->txsc.always_tx_sci = always_tx_sci;

    return NETOS_STATUS_SUCCESS;
}

netos_status macsec_context::create_rxsc(uint8_t *sci,
                                         bool replay_protect, 
                                         uint8_t replay_window)
{
    macsec_secy *secy = NULL;
    bool found;

    found = this->secy_list_->find(sci, &secy);
    if (!found) {
        return netos_status::NETOS_STATUS_MACSEC_SECY_NOT_FOUND;
    }

    memcpy(secy->rxsc.sci, sci, MACSEC_SCI_LEN);
    secy->rxsc.replay_protect = replay_protect;
    secy->rxsc.replay_window = replay_window;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status macsec_context::create_txsa(uint8_t *sci, macsec_txsa *txsa)
{
    macsec_secy *secy = NULL;
    bool found;

    if (txsa->an > MACSEC_AN_MAX) {
        return netos_status::NETOS_STATUS_MACSEC_AN_INVAL;
    }

    found = this->secy_list_->find(sci, &secy);
    if (!found) {
        return netos_status::NETOS_STATUS_MACSEC_SECY_NOT_FOUND;
    }

    secy->txsc.txsa[txsa->an].an                    = txsa->an;
    secy->txsc.txsa[txsa->an].next_pn               = txsa->next_pn;
    memcpy(secy->txsc.txsa[txsa->an].key, txsa->key, txsa->key_len);
    secy->txsc.txsa[txsa->an].key_len               = txsa->key_len;
    secy->txsc.txsa[txsa->an].protect_frames        = txsa->protect_frames;
    secy->txsc.txsa[txsa->an].macsec_operational    = false;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status macsec_context::create_rxsa(uint8_t *sci,
                                         macsec_rxsa *rxsa)
{
    macsec_secy *secy = NULL;
    bool found;

    if (rxsa->an > 3) {
        return netos_status::NETOS_STATUS_MACSEC_AN_INVAL;
    }

    found = this->secy_list_->find(sci, &secy);
    if (!found) {
        return netos_status::NETOS_STATUS_MACSEC_SECY_NOT_FOUND;
    }

    secy->rxsc.rxsa[rxsa->an].an                    = rxsa->an;
    secy->rxsc.rxsa[rxsa->an].next_pn               = rxsa->next_pn;
    secy->rxsc.rxsa[rxsa->an].lowest_pn             = rxsa->lowest_pn;
    memcpy(secy->rxsc.rxsa[rxsa->an].key, rxsa->key, rxsa->key_len);
    secy->rxsc.rxsa[rxsa->an].key_len               = rxsa->key_len;
    secy->rxsc.rxsa[rxsa->an].protect_frames        = rxsa->protect_frames;
    secy->rxsc.rxsa[rxsa->an].macsec_operational    = false;

    return netos_status::NETOS_STATUS_SUCCESS;
}

void macsec_context::deinitialize()
{

}

netos_status macsec_context::enable_txsa(uint8_t *sci, uint32_t an)
{
    macsec_secy *secy = NULL;
    bool found;

    found = this->secy_list_->find(sci, &secy);
    if (!found) {
        return netos_status::NETOS_STATUS_MACSEC_SECY_NOT_FOUND;
    }

    secy->txsc.txsa[an].macsec_operational = true;

    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status macsec_context::enable_rxsa(uint8_t *sci, uint32_t an)
{
    macsec_secy *secy = NULL;
    bool found;

    found = this->secy_list_->find(sci, &secy);
    if (!found) {
        return netos_status::NETOS_STATUS_MACSEC_SECY_NOT_FOUND;
    }

    secy->rxsc.rxsa[an].macsec_operational = true;

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

