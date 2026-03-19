#ifndef PROTOCOLS_ETHERTYPES_H
#define PROTOCOLS_ETHERTYPES_H

namespace netos {

namespace ids {

/**
 * @brief - Defines a List of ethertypes.
 */
#define NETOS_ETHERTYPE_IPV4                0x0800
#define NETOS_ETHERTYPE_IPV6                0x86DD
#define NETOS_ETHERTYPE_ARP                 0x0806
#define NETOS_ETHERTYPE_VLAN                0x8100
#define NETOS_ETHERTYPE_AVTP                0x22F0
#define NETOS_ETHERTYPE_NONSTD_VLAN         0x9100
#define NETOS_ETHERTYPE_IEEE_802AD          0x88A8
#define NETOS_ETHERTYPE_MACSEC              0x88E5
#define NETOS_ETHERTYPE_MKA                 0x888E
#define NETOS_ETHERTYPE_8021BR              0x893F

}

}

#endif

