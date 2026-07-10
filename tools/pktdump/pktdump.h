#ifndef NETOS_PKTDUMP_H
#define NETOS_PKTDUMP_H

#include <stdint.h>
#include <time.h>
#include <ncurses.h>
#include "raw_socket.h"
#include "netos_status.h"

/* -------------------------------------------------------------------------
 * Window layout
 * -------------------------------------------------------------------------
 * +-----------------------------------------------------------------------+
 * | top_win  (1 row, full width — title bar)                              |
 * +-----------------------------------------------------------------------+
 * |                                                                       |
 * | packet_win (70% of remaining height — scrolling decoded packet log)   |
 * |                                                                       |
 * +-----------------------------------------------------------------------+
 * | stats_win  (30% of remaining height — live statistics panel)          |
 * +-----------------------------------------------------------------------+
 */
typedef struct {
    WINDOW *top_win;           /**< Fixed single-row title bar.               */
    WINDOW *packet_border_win; /**< Border container window for packet_win.   */
    WINDOW *packet_win;        /**< Scrolling decoded packet log (inner win). */
    WINDOW *stats_border_win;  /**< Border container window for stats_win.    */
    WINDOW *stats_win;         /**< Live statistics pane (inner stats win).   */
} netos_pktdump_window_t;

/* -------------------------------------------------------------------------
 * Per-protocol packet counters
 * ------------------------------------------------------------------------- */
typedef struct {
    uint64_t rx_pkts;    /**< Total received packets.      */
    uint64_t rx_bytes;   /**< Total received bytes.        */
    uint64_t arp;        /**< ARP frames.                  */
    uint64_t ipv4;       /**< IPv4 frames.                 */
    uint64_t ipv6;       /**< IPv6 frames.                 */
    uint64_t tcp;        /**< TCP segments (over IPv4/6).  */
    uint64_t udp;        /**< UDP datagrams (over IPv4/6). */
    uint64_t icmp;       /**< ICMPv4 messages.             */
    uint64_t icmp6;      /**< ICMPv6 messages.             */
    uint64_t other;      /**< Unknown / unsupported proto. */
    struct timespec start_time;       /**< When capture began.        */
    struct timespec last_update_time; /**< Last time UI was updated.  */
} netos_pktdump_stats_t;

/* -------------------------------------------------------------------------
 * Top-level context — passed throughout all subsystems
 * ------------------------------------------------------------------------- */
typedef struct {
    netos_pktdump_window_t  window;  /**< ncurses window handles.           */
    netos_pktdump_stats_t   stats;   /**< Live counters.                    */
    netos_raw_socket_ctx_t *raw;     /**< Raw socket context (RX).          */
    const char             *ifname;  /**< Captured interface name.          */
} netos_pktdump_ctx_t;

#endif /* NETOS_PKTDUMP_H */
