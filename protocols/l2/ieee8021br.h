#ifndef PROTOCOLS_L2_8021BR_H
#define PROTOCOLS_L2_8021BR_H

#include <cstdint>

#include "error_codes.h"
#include "packet_buf.h"

#define NETOS_IEEE8021BR_HDR_LEN    8u

namespace netos {

struct ieee8021br_hdr {
    uint32_t e_pcp              : 3;
    uint32_t e_dei              : 1;
    uint32_t ingress_ecid_base  : 12;
    uint32_t reserved           : 2;
    uint32_t grp                : 2;
    uint32_t ecid_base          : 12;
    uint8_t target_ecid;
    uint8_t ecid_ext;
    uint16_t ethertype;

    netos_status serialize(packet_buf *pkt_buf);
    netos_status deserialize(packet_buf *pkt_buf);
};

}

#endif


