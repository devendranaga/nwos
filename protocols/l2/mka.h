#ifndef PROTOCOLS_L2_MKA_H
#define PROTOCOLS_L2_MKA_H

#include <stdint.h>
#include "packet_buf.h"
#include "event_mgr.h"
#include "error_codes.h"

#define IEEE8021X_VERSION_2010              0x03
#define IEEE8021X_TYPE_MKA                  0x05

#define MKA_POTENTIAL_HDR                   0x0001
#define MKA_LIVE_PEER_HDR                   0x0002
#define MKA_DIST_SAK_HDR                    0x0004
#define MKA_MACSEC_SAK_HDR                  0x0008
#define MKA_ICV_HDR                         0x0010

#define MKA_SCI_LEN                         6
#define MKA_MI_LEN                          12
#define MKA_CKN_LEN                         32
#define MKA_ICV_LEN                         16
#define MKA_BASIC_PARAM_LEN_NO_CKN          (4 + MKA_SCI_LEN + MKA_MI_LEN + 4 + 4)
#define MKA_AES_WRAP_LEN                    40
#define MKA_MAX_PEERS                       16
#define MKA_MACSEC_DIST_PARAM_LEN_DEFAULT   40

/**
 * @brief - Defines parameter set types in MKA 2020.
 */
#define MKA_LIVE_PEER_PARAM_TYPE            1
#define MKA_POTENTIAL_PEER_PARAM_TYPE       2
#define MKA_MACSEC_SAK_USE_PARAM_TYPE       3
#define MKA_DIST_SAK_PARAM_TYPE             4
#define MKA_ICV_PARAM_TYPE                  255

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
    uint16_t            n_peers;
    struct mka_peer {
        uint8_t         peer_mi[MKA_MI_LEN];
        uint32_t        peer_mn;
    } peers [MKA_MAX_PEERS];

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

/**
 * @brief - Defines MKA live peeer parameter set.
 */
struct mka_live_peer_header {
    uint16_t            n_peers;
    struct mka_peer {
        uint8_t         peer_mi[MKA_MI_LEN];
        uint32_t        peer_mn;
    } peers [MKA_MAX_PEERS];

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

/**
 * @brief - Defines Distributed SAK header options.
 */
struct mka_dist_sak_header_opt {
    uint32_t            dist_an             : 2;
    uint32_t            conf_off            : 2;
    uint32_t            reserved            : 8;
    uint32_t            paramset_body_len   : 12;
    uint32_t            reserved_2          : 8;
} __attribute__ ((__packed__));

/**
 * @brief - Defines Distributed SAK parameter set.
 */
struct mka_dist_sak_header {
    mka_dist_sak_header_opt opt;
    uint32_t kn;
    uint32_t aes_keywrap_len;
    uint8_t *aes_wrap;

    explicit mka_dist_sak_header() { }
    ~mka_dist_sak_header() { }

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

/**
 * @brief - Defines MACsec SAK options.
 */
struct mka_macsec_sak_header_opt {
    uint32_t            lan                 : 2;
    uint32_t            ltx                 : 1;
    uint32_t            lrx                 : 1;
    uint32_t            oan                 : 2;
    uint32_t            otx                 : 1;
    uint32_t            orx                 : 1;
    uint32_t            ptx                 : 1;
    uint32_t            prx                 : 1;
    uint32_t            reserved            : 1;
    uint32_t            dp                  : 1;
    uint32_t            paramset_body_len   : 12;
    uint32_t            reserved_2          : 8;
} __attribute__ ((__packed__));

/**
 * @brief - Defines MACsec SAK parameter set.
 */
struct mka_macsec_sak_header {
    mka_macsec_sak_header_opt   opt;
    uint8_t                     latest_mi[MKA_MI_LEN];
    uint32_t                    latest_kn;
    uint32_t                    latest_lowest_pn;
    uint8_t                     oldest_mi[MKA_MI_LEN];
    uint32_t                    oldest_kn;
    uint32_t                    oldest_lowest_pn;

    explicit mka_macsec_sak_header() { }
    ~mka_macsec_sak_header() { }

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
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

