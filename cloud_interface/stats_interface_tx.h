#ifndef NETOS_STATS_INTERFACE_TX_H
#define NETOS_STATS_INTERFACE_TX_H

#if defined(__cplusplus)
extern "C" {
#endif

struct netos_stats_interface_tx {
    uint64_t n_rx;
    uint64_t n_eth;
} __attribute__ ((__packed__));

inline uint32_t netos_stats_intf_get_tx_msg_len()
{
    return sizeof(struct netos_stats_interface_tx);
}

#if defined(__cplusplus)
}
#endif

#endif

