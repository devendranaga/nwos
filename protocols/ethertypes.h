#ifndef NETOS_ETHERTYPES_H
#define NETOS_ETHERTYPES_H

/**
 * @brief - Defines a list of ethertypes.
 */
typedef enum {
    NETOS_ETHERTYPE_ARP             = 0x0806,
    NETOS_ETHERTYPE_RARP            = 0x8035,
    NETOS_ETHERTYPE_VLAN            = 0x8100,
    NETOS_ETHERTYPE_NON_STD_VLAN    = 0x9100,
    NETOS_ETHERTYPE_8021AD          = 0x88A8,
    NETOS_ETHERTYPE_MACSEC          = 0x88E5,
    NETOS_ETHERTYPE_IPV4            = 0x0800,
    NETOS_ETHERTYPE_IPV6            = 0x86DD,
    NETOS_ETHERTYPE_IEEE_8021QBB    = 0x8808,
} netos_ethertype_t;

#endif
