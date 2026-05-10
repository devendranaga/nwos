#include "network_config.h"
#include "ioctl_nw.h"
#include "vlan_membership.h"

namespace netos {

#if 0
void for_each_callback(uint32_t butcket_no, void *item)
{
    vlan_entry *entry = (vlan_entry *)item;
    printf("bucket %d interface %s\n", butcket_no, entry->intf.c_str());
}
#endif

void vlan_membership::initialize()
{
    network_config *config = network_config::instance();

    //netos_hash_table_for_each(this->vlan_table_, for_each_callback);
}

}
