#ifndef PROTOCOLS_L2_MACSEC_H
#define PROTOCOLS_L2_MACSEC_H

#include <stdint.h>
#include <string.h>

#include "netos_macros.h"
#include "error_codes.h"
#include "cryptography_methods.h"
#include "cryptography_aes_gcm.h"
#include "hash_table.h"
#include "packet_buf.h"
#include "parsed_pkt.h"

namespace netos {

using namespace netos::lib;

#define MACSEC_SCI_LEN  8
#define MACSEC_SA_LEN   4
#define MACSEC_AN_MAX   3
#define MACSEC_KEY_LEN  32

enum class macsec_cipher_info {
    GCM_AES_128,
    GCM_AES_256,
    GCM_AES_XPN_128,
    GCM_AES_XPN_256,
};

struct macsec_txsa {
    bool protect_frames;
    uint32_t an;
    uint32_t next_pn;
    uint8_t key[MACSEC_KEY_LEN];
    uint32_t key_len;
    bool macsec_operational;
    std::shared_ptr<cryptography_aes_gcm> gcm_;
    std::shared_ptr<cryptography_aes_gmac> gmac_;
};

struct macsec_rxsa {
    bool protect_frames;
    uint64_t lowest_pn;
    uint64_t next_pn;
    uint32_t an;
    uint8_t key[MACSEC_KEY_LEN];
    uint32_t key_len;
    bool macsec_operational;
    std::shared_ptr<cryptography_aes_gcm> gcm_;
    std::shared_ptr<cryptography_aes_gmac> gmac_;
};

struct macsec_rxsc {
    uint8_t sci[MACSEC_SCI_LEN];
    bool replay_protect;
    uint32_t replay_window;
    macsec_rxsa rxsa[MACSEC_SA_LEN];
};

struct macsec_txsc {
    uint8_t sci[MACSEC_SCI_LEN];
    bool always_tx_sci;
    macsec_txsa txsa[MACSEC_SA_LEN];
};

struct macsec_secy {
    macsec_cipher_info cipher;
    uint8_t sci[MACSEC_SCI_LEN]; // can be txsci or rxsci
    macsec_txsc txsc;
    macsec_rxsc rxsc;
};

class macsec_context {
    public:
        explicit macsec_context() = default;
        ~macsec_context() = default;

        netos_status initialize(uint32_t n_secy, uint32_t n_rxsc);
        netos_status create_secy(macsec_cipher_info cipher, uint8_t *sci);
        netos_status create_txsc(uint8_t *sci,
                                 bool always_tx_sci);
        netos_status create_rxsc(uint8_t *sci,
                                 bool replay_protect,
                                 uint8_t replay_window);
        netos_status create_txsa(uint8_t *sci,
                                 macsec_txsa *txsa);
        netos_status create_rxsa(uint8_t *sci,
                                 macsec_rxsa *rxsa);
        netos_status enable_txsa(uint8_t *sci, uint32_t an);
        netos_status enable_rxsa(uint8_t *sci, uint32_t an);
        void deinitialize();

        netos_status transmit(uint8_t *sci, bool use_es, packet_buf *pkt_buf);
        netos_status receive(parsed_pkt *parsed_pkt);

    private:
        hash_table<uint8_t *, macsec_secy *> *secy_list_;

        uint32_t hash_sci(uint8_t *sci) {
            uint32_t sci_hash = 0;

            sci_hash = (sci[7] << 24) + (sci[6] << 16) + (sci[5] << 8) + sci[4] +
                       (sci[3] << 24) + (sci[2] << 16) + (sci[1] << 8) + sci[0];

            return sci_hash;
        }

        bool find_sci(uint8_t *sci_1, uint8_t *sci_2) {
            return memcmp(sci_1, sci_2, NETOS_MACADDR_LEN);
        }

        void del_sci(uint8_t *sci_1, macsec_secy *secy) {
            return;
        }

        bool for_each_sci(uint8_t *sci, macsec_secy *secy) {
            return false;
        }
};

class macsec_mgr {
    public:
        explicit macsec_mgr();
        ~macsec_mgr();

    private:
        macsec_context ctx_;
};

}

#endif

