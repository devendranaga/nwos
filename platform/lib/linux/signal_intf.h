#ifndef PLATFORM_LIB_SIGNAL_INTF_H
#define PLATFORM_LIB_SIGNAL_INTF_H

#include <stdint.h>
#include <signal.h>

#if defined(__cplusplus)
extern "C" {
#endif

inline void netos_block_signals(uint32_t *signal_list, uint32_t signal_list_len)
{
    sigset_t sigmask;
    uint32_t i;

    sigemptyset(&sigmask);
    for (i = 0; i < signal_list_len; i++) {
        sigaddset(&sigmask, signal_list[i]);
    }

    sigprocmask(SIG_BLOCK, &sigmask, NULL);
}

inline void netos_block_term_signals()
{
    uint32_t signals[2] = {SIGINT, SIGTERM};

    netos_block_signals(signals, sizeof(signals) / sizeof(signals[0]));
}

#if defined(__cplusplus)
}
#endif

#endif

