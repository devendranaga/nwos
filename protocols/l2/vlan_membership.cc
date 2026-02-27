#include "network_config.h"
#include "ioctl_nw.h"
#include "vlan_membership.h"

static uint32_t vlan_membership_hash_fn(void *key)
{
    uint8_t *mac = (uint8_t *)key;
    uint32_t hash = 0;
    for (uint32_t i = 0; i < NETOS_MACADDR_LEN; i++) {
        hash = (hash << 5) - hash + mac[i];
    }
    return hash;
}

namespace netos {

void vlan_membership::initialize()
{
    network_config *config = network_config::instance();

    this->vlan_table_ = netos_hash_table_init(16); // 16 interfaces
    for (auto vlan_config : config->vlan_config_.vlan_mapping) {
        for (auto vlan_map_item : vlan_config.vlan_id_map) {
            vlan_entry *entry = new vlan_entry();
            if (!entry) {
                return;
            }

            entry->intf = vlan_config.ifname;
            entry->ingress_vlan_id = vlan_map_item.ingress_vlan_id;
            entry->egress_vlan_id = vlan_map_item.egress_vlan_id;
            netos_get_macaddr(vlan_config.ifname.c_str(), entry->mac);
            netos_hash_table_add_item(this->vlan_table_, entry, entry->mac, vlan_membership_hash_fn);
        }
    }
}

}
