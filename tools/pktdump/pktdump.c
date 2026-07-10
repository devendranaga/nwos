/**
 * @file   pktdump.c
 * @brief  netos_pktdump — live packet capture & decode with ncurses UI.
 *
 * Usage:
 *   netos_pktdump -i <interface>
 *
 * Architecture:
 *   - A single main thread blocks on netos_raw_socket_rx().
 *   - Each received frame is decoded by netos_pktdump_decode() into a
 *     one-line string, which is appended to the scrolling left pane.
 *   - After each packet the statistics pane is refreshed.
 *   - SIGINT / SIGTERM trigger a clean shutdown.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

#include "netos_status.h"
#include "raw_socket.h"
#include "pktdump.h"
#include "pktdump_ui.h"
#include "pktdump_decoder.h"

/* -------------------------------------------------------------------------
 * Constants
 * ------------------------------------------------------------------------- */

/** Maximum single-packet line length shown in the left pane. */
#define PKTDUMP_LINE_MAXLEN  512

/** Receive buffer size — enough for a maximum Ethernet frame. */
#define PKTDUMP_RX_BUF_LEN  9000

/* -------------------------------------------------------------------------
 * Signal handling
 * ------------------------------------------------------------------------- */

/** Set to 1 by the signal handler; checked in the RX loop. */
static volatile sig_atomic_t g_stop = 0;

static void pktdump_signal_handler(int signum)
{
    (void)signum;
    g_stop = 1;
}

static void pktdump_register_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = pktdump_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* -------------------------------------------------------------------------
 * Statistics update
 * ------------------------------------------------------------------------- */

/**
 * @brief Increment the per-protocol counter corresponding to @p proto.
 *
 * Also increments the total rx_pkts and rx_bytes counters.
 *
 * @param stats  Pointer to the statistics struct.
 * @param proto  Protocol classification from the decoder.
 * @param bytes  Number of bytes in the received frame.
 */
static void pktdump_update_stats(netos_pktdump_stats_t *stats,
                                 pktdump_proto_t        proto,
                                 int                    bytes)
{
    stats->rx_pkts++;
    stats->rx_bytes += (uint64_t)bytes;

    switch (proto) {
        case PKTDUMP_PROTO_ARP:       stats->arp++;   break;
        case PKTDUMP_PROTO_IPV4_TCP:  stats->tcp++;   stats->ipv4++; break;
        case PKTDUMP_PROTO_IPV4_UDP:  stats->udp++;   stats->ipv4++; break;
        case PKTDUMP_PROTO_IPV4_ICMP: stats->icmp++;  stats->ipv4++; break;
        case PKTDUMP_PROTO_IPV6:      stats->ipv6++;  break;
        default:                      stats->other++; break;
    }
}

/* -------------------------------------------------------------------------
 * CLI argument parsing
 * ------------------------------------------------------------------------- */

static void pktdump_print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -i <interface>\n", prog);
    fprintf(stderr, "  -i <interface>   Network interface to capture from\n");
    fprintf(stderr, "  -h               Show this help\n");
}

static const char *pktdump_parse_args(int argc, char *argv[])
{
    int opt;
    const char *ifname = NULL;

    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 'h':
                pktdump_print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            default:
                pktdump_print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!ifname) {
        fprintf(stderr, "Error: -i <interface> is required\n\n");
        pktdump_print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    return ifname;
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *ifname = pktdump_parse_args(argc, argv);

    /* --- Context initialisation --- */
    netos_pktdump_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ifname = ifname;

    /* --- Open raw socket --- */
    ctx.raw = netos_raw_socket_init(ifname);
    if (!ctx.raw) {
        fprintf(stderr, "Failed to open raw socket on '%s' "
                        "(are you running as root?)\n", ifname);
        return EXIT_FAILURE;
    }

    /* --- Register signal handlers before ncurses takes the terminal --- */
    pktdump_register_signals();

    /* --- Initialize ncurses UI --- */
    netos_status_t ret = netos_pktdump_ui_init(&ctx, ifname);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_raw_socket_deinit(ctx.raw);
        return EXIT_FAILURE;
    }

    /* --- RX loop --- */
    uint8_t rx_buf[PKTDUMP_RX_BUF_LEN];
    char    line[PKTDUMP_LINE_MAXLEN];

    while (!g_stop) {
        int rx_len = netos_raw_socket_rx(ctx.raw, rx_buf, sizeof(rx_buf));
        if (rx_len <= 0) {
            /* Interrupted by signal or error — check g_stop. */
            continue;
        }

        /* Decode the raw frame into a human-readable line. */
        pktdump_proto_t proto =
            netos_pktdump_decode(rx_buf, rx_len, line, sizeof(line));

        /* Update statistics counters. */
        pktdump_update_stats(&ctx.stats, proto, rx_len);

        /* Append line to the scrolling packet pane. */
        netos_pktdump_ui_append_line(&ctx, line);

        /* Refresh the statistics pane. */
        netos_pktdump_ui_refresh_stats(&ctx);
    }

    /* --- Cleanup --- */
    netos_pktdump_ui_cleanup(&ctx);
    netos_raw_socket_deinit(ctx.raw);

    return EXIT_SUCCESS;
}
