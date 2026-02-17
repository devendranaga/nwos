#ifndef NETOS_PROTOCOLS_L2_MACSEC_H
#define NETOS_PROTOCOLS_L2_MACSEC_H

#include <stdint.h>
#include "packet_buf.h"
#include "error_codes.h"

#define NETOS_MACSEC_IV_LEN 16
#define NETOS_MACSEC_HDR_MIN_LEN 22 // includes 6 byte header no sci but with ICV

namespace netos {

struct macsec_tci {
    uint32_t ver :1;
    uint32_t es  :1;
    uint32_t sc  :1;
    uint32_t scb :1;
    uint32_t e   :1;
    uint32_t c   :1;
    uint32_t an  :2;

    explicit macsec_tci() { }
    ~macsec_tci() { }
};

struct macsec_sci {
    uint8_t     mac[NETOS_MACADDR_LEN];
    uint16_t    port_id;

    explicit macsec_sci() { }
    ~macsec_sci() { }
};

struct macsec_hdr {
    macsec_tci    tci;
    uint8_t       short_len;
    uint32_t      pn;
    macsec_sci    sci;
    uint16_t      ethertype;
    uint16_t      data_len;
    uint8_t       *data;
    uint8_t       iv[NETOS_MACSEC_IV_LEN];

    explicit macsec_hdr() { }
    ~macsec_hdr() { }

    netos_status serialize(packet_buf *buf);
    netos_status deserialize(packet_buf *buf);
    void print();
};

}

#endif
