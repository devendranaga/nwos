#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "virt_intf.h"

netos_status_t netos_virt_if_init(const char *ifname)
{
    netos_virt_if_t *virt;

    virt = calloc(1, sizeof(netos_virt_if_t));
    if (!virt) {
        return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
    }

    virt->ifname = strdup(ifname);

    return NETOS_STATUS_SUCCESS;
}

