#ifndef PROTOCOLS_L2_VLAN_H
#define PROTOCOLS_L2_VLAN_H

#include <stdint.h>
#include <memory>

#include "error_codes.h"
#include "packet_buf.h"

namespace netos {

#define NETOS_IDS_VLAN_HDR_LEN 4

struct vlan_hdr {
    uint32_t priority:3;
    uint32_t dei:1;
    uint32_t vid:12;
    uint16_t ethertype;

    explicit vlan_hdr() : priority(0),
                          dei(0),
                          vid(0),
                          ethertype(0)
    {
    }

    ~vlan_hdr()
    {
    }

    netos_status serialize(std::shared_ptr<packet_buf> &pkt_buf);
    netos_status deserialize(std::shared_ptr<packet_buf> &pkt_buf);
    void print();
};

}

#endif
