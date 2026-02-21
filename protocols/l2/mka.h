#ifndef PROTOCOLS_L2_MKA_H
#define PROTOCOLS_L2_MKA_H

#include <stdint.h>
#include "packet_buf.h"
#include "error_codes.h"

#define IEEE8021X_VERSION_2010      0x03
#define IEEE8021X_TYPE_MKA          0x05

#define MKA_POTENTIAL_HDR           0x0001
#define MKA_LIVE_PEER_HDR           0x0002
#define MKA_DIST_SAK_HDR            0x0004
#define MKA_MACSEC_SAK_HDR          0x0008

#define MKA_SCI_LEN                 6
#define MKA_MI_LEN                  12
#define MKA_CKN_LEN                 32
#define MKA_ICV_LEN                 16

#define MKA_LIVE_PEER_PARAM_TYPE        1
#define MKA_POTENTIAL_PEER_PARAM_TYPE   2
#define MKA_ICV_PARAM_TYPE              255

namespace netos {

/**
 * @brief - Defines Basic parameter options.
 */
struct mka_basic_params {
    uint32_t key_server             : 1;
    uint32_t macsec_desired         : 1;
    uint32_t macsec_capability      : 2;
    uint32_t paramset_body_len      : 12;
} __attribute__ ((__packed__));

/**
 * @brief - Defines ICV header.
 */
struct mka_icv_header {
    uint16_t paramset_body_len;
    uint8_t icv[MKA_ICV_LEN];

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

/**
 * @brief - Defines MKA Basic parameter set.
 */
struct mka_basic_header {
    uint8_t             version;
    uint8_t             key_server_priority;
    mka_basic_params    opts;
    uint8_t             sci[MKA_SCI_LEN];
    uint8_t             mi[MKA_MI_LEN];
    uint32_t            mn;
    uint32_t            algorithm_agility;
    uint32_t            ckn_len;
    uint32_t            ckn[MKA_CKN_LEN];

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

/**
 * @brief - Defines MKA potential peer parameter set.
 */
struct mka_potential_peer_header {
    uint16_t            paramset_body_len;
    uint8_t             peer_mi[MKA_MI_LEN];
    uint32_t            peer_mn;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

/**
 * @brief - Defines MKA live peeer parameter set.
 */
struct mka_live_peer_header {
    uint16_t            paramset_body_len;
    uint8_t             peer_mi[MKA_MI_LEN];
    uint32_t            peer_mn;
};

struct mka_dist_sak_header {
};

struct mka_macsec_sak_header {
};

/**
 * @brief - Defines MKA header.
 */
struct mka_header {
    uint32_t                    available_headers;

    /**
     * Basic params is mandatory and rest of the headers
     * will be either present or absent depending on where
     * MKA state is.
     */
    mka_basic_header            bh;
    mka_potential_peer_header   ph;
    mka_live_peer_header        lh;
    mka_dist_sak_header         dh;
    mka_macsec_sak_header       mh;
    mka_icv_header              ih;

    explicit mka_header() { }
    ~mka_header() { }

    netos_status serialize(packet_buf *buf);
    netos_status deserialize(packet_buf *buf);
};

/**
 * @brief - Defines IEEE 802.1x MKA header.
 */
struct ieee8021x_header {
    uint8_t         version;
    uint8_t         type;
    uint16_t        len;
    mka_header      mh;

    netos_status serialize(packet_buf *buf);
    netos_status deserialize(packet_buf *buf);
};

}

#endif

