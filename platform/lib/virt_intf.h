#ifndef NETOS_VIRT_INTF_H
#define NETOS_VIRT_INTF_H

#include "netos_status.h"

typedef struct netos_virt_macsec_if {
    void                        *tx_secy_inst;
    void                        *rx_secy_inst;
    struct netos_virt_macsec_if *next;
} netos_virt_macsec_if_t;

typedef struct {
    const char              *ifname;
    netos_virt_macsec_if_t  *macsec_intf;
} netos_virt_if_t;

netos_status_t netos_virt_if_init(const char *ifname);

#endif


