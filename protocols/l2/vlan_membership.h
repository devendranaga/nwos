#ifndef PROTOCOLS_L2_VLAN_MEMBERSHIP_H
#define PROTOCOLS_L2_VLAN_MEMBERSHIP_H

#include <iostream>
#include <stdint.h>
#include "netos_macros.h"
#include "hash_table.h"

namespace netos {

struct vlan_entry {
    std::string intf;
    uint8_t mac[NETOS_MACADDR_LEN];
    uint16_t ingress_vlan_id;
    uint16_t egress_vlan_id;
};

class vlan_membership {
    public:
        static vlan_membership *instance()
        {
            static vlan_membership instance;
            return &instance;
        }
        ~vlan_membership() = default;

        void initialize();

    private:
        netos_hash_table *vlan_table_;

        explicit vlan_membership() = default;
};

}

#endif
