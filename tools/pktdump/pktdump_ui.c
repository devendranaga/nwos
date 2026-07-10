/**
 * @file   pktdump_ui.c
 * @brief  ncurses UI subsystem for netos_pktdump.
 *
 * Manages window layout with borders and color styling:
 *   top_win           — 1-row highlighted title bar
 *   packet_border_win — parent container for packet log borders (bold)
 *   packet_win        — inner scrolling decoded packet log window
 *   stats_border_win  — parent container for stats borders (bold)
 *   stats_win         — inner statistics display window
 *
 * Thread-safety: All functions must be called from the same thread (ncurses
 * WINDOW* operations are not thread-safe by design).
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <ncurses.h>

#include "netos_status.h"
#include "pktdump.h"
#include "pktdump_ui.h"

/* Color pair IDs */
#define COLOR_PAIR_BLUE    1
#define COLOR_PAIR_GREEN   2
#define COLOR_PAIR_RED     3

/* -------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

/** Draw the fixed top title bar. */
static void ui_draw_title_bar(netos_pktdump_ctx_t *ctx, const char *ifname)
{
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);
    (void)max_y;

    char title[256];
    snprintf(title, sizeof(title),
             " netos_pktdump  |  interface: %s  |  press Ctrl-C to stop",
             ifname ? ifname : "?");

    wattron(ctx->window.top_win, A_REVERSE | A_BOLD);
    wmove(ctx->window.top_win, 0, 0);
    wprintw(ctx->window.top_win, "%-*s", max_x, title);
    wattroff(ctx->window.top_win, A_REVERSE | A_BOLD);
    wrefresh(ctx->window.top_win);
}

/** Format a byte count into a human-readable string (B / KB / MB / GB). */
static void ui_fmt_bytes(uint64_t bytes, char *buf, size_t buf_len)
{
    if (bytes < 1024ULL) {
        snprintf(buf, buf_len, "%" PRIu64 " B", bytes);
    } else if (bytes < 1024ULL * 1024ULL) {
        snprintf(buf, buf_len, "%.1f KB", (double)bytes / 1024.0);
    } else if (bytes < 1024ULL * 1024ULL * 1024ULL) {
        snprintf(buf, buf_len, "%.1f MB",
                 (double)bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buf, buf_len, "%.2f GB",
                 (double)bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

/** Compute elapsed seconds since capture started. */
static double ui_elapsed_seconds(const netos_pktdump_stats_t *stats)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec  - stats->start_time.tv_sec) +
           (double)(now.tv_nsec - stats->start_time.tv_nsec) * 1e-9;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

netos_status_t netos_pktdump_ui_init(netos_pktdump_ctx_t *ctx,
                                     const char          *ifname)
{
    initscr();
    cbreak();
    noecho();
    curs_set(0);   /* Hide blinking cursor. */
    keypad(stdscr, TRUE);

    /* Initialize color support if available */
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(COLOR_PAIR_BLUE,   COLOR_BLUE,  -1); /* Blue */
        init_pair(COLOR_PAIR_GREEN,  COLOR_GREEN, -1); /* Green */
        init_pair(COLOR_PAIR_RED,    COLOR_RED,   -1); /* Bright red */
    }

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    /* Minimum size guard. */
    if (max_y < 10 || max_x < 40) {
        endwin();
        fprintf(stderr, "Terminal window is too small "
                        "(min 10 rows × 40 cols required for boxed layout)\n");
        return NETOS_STATUS_INIT_SCREEN_FAILURE;
    }

    /* -----------------------------------------------------------------------
     * Layout calculation (Horizontal Split with Boxes)
     *   top_win          : 1 row, full width, at y=0
     *   packet_border_win: 70% of remaining height, full width, at y=1
     *   packet_win       : inner scrolling region (newwin positioned inside border)
     *   stats_border_win : remaining 30% height, full width, at y=1+packet_height
     *   stats_win        : inner stats region (newwin positioned inside border)
     * --------------------------------------------------------------------- */
    int top_height     = 1;
    int content_height = max_y - top_height;
    int packet_height  = (content_height * 70) / 100;
    int stats_height   = content_height - packet_height;

    ctx->window.top_win           = newwin(top_height,     max_x, 0, 0);
    ctx->window.packet_border_win = newwin(packet_height,  max_x, top_height, 0);
    ctx->window.packet_win        = newwin(packet_height - 2, max_x - 2, top_height + 1, 1);
    ctx->window.stats_border_win  = newwin(stats_height,   max_x, top_height + packet_height, 0);
    ctx->window.stats_win         = newwin(stats_height - 2,  max_x - 2, top_height + packet_height + 1, 1);

    if (!ctx->window.top_win || !ctx->window.packet_border_win ||
        !ctx->window.packet_win || !ctx->window.stats_border_win || !ctx->window.stats_win) {
        endwin();
        return NETOS_STATUS_INIT_SCREEN_FAILURE;
    }

    /* Draw container box for the packet log window in bold */
    wattron(ctx->window.packet_border_win, A_BOLD);
    box(ctx->window.packet_border_win, 0, 0);
    mvwprintw(ctx->window.packet_border_win, 0, 2, " PACKET LOG ");
    wattroff(ctx->window.packet_border_win, A_BOLD);
    wrefresh(ctx->window.packet_border_win);

    /* Draw container box for the statistics window in bold */
    wattron(ctx->window.stats_border_win, A_BOLD);
    box(ctx->window.stats_border_win, 0, 0);
    mvwprintw(ctx->window.stats_border_win, 0, 2, " STATISTICS ");
    wattroff(ctx->window.stats_border_win, A_BOLD);
    wrefresh(ctx->window.stats_border_win);

    /* Enable auto-scroll only for the inner packet log window. */
    scrollok(ctx->window.packet_win, TRUE);

    /* Record capture start time. */
    clock_gettime(CLOCK_MONOTONIC, &ctx->stats.start_time);

    /* Initialize last update time to 0 to force the first refresh immediately. */
    memset(&ctx->stats.last_update_time, 0, sizeof(struct timespec));

    /* Initial draw. */
    ui_draw_title_bar(ctx, ifname);
    netos_pktdump_ui_refresh_stats(ctx);

    return NETOS_STATUS_SUCCESS;
}

void netos_pktdump_ui_append_line(netos_pktdump_ctx_t *ctx,
                                  const char          *line)
{
    int max_y, max_x;
    getmaxyx(ctx->window.packet_win, max_y, max_x);
    (void)max_y;

    char formatted[1024];
    snprintf(formatted, sizeof(formatted), "%6" PRIu64 "  %s", ctx->stats.rx_pkts, line);

    /* Prevent text wrapping which corrupts ncurses scrolling geometry.
     * We truncate long lines (common in IPv6) and append an ellipsis "..." */
    int len = (int)strlen(formatted);
    if (len >= max_x) {
        if (max_x > 5) {
            formatted[max_x - 4] = '.';
            formatted[max_x - 3] = '.';
            formatted[max_x - 2] = '.';
            formatted[max_x - 1] = '\0';
        } else {
            formatted[max_x - 1] = '\0';
        }
    }

    wprintw(ctx->window.packet_win, "%s\n", formatted);
}

void netos_pktdump_ui_refresh_stats(netos_pktdump_ctx_t *ctx)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Skip rate limit check on the first draw (when last_update_time is zero). */
    if (ctx->stats.last_update_time.tv_sec != 0 || ctx->stats.last_update_time.tv_nsec != 0) {
        /* Calculate elapsed time since last screen update in milliseconds. */
        long elapsed_ms = (now.tv_sec - ctx->stats.last_update_time.tv_sec) * 1000L +
                          (now.tv_nsec - ctx->stats.last_update_time.tv_nsec) / 1000000L;

        /* Rate limit rendering updates to 40ms (~25 FPS) for high performance and low latency. */
        if (elapsed_ms < 40L) {
            return;
        }
    }

    ctx->stats.last_update_time = now;

    WINDOW                      *w = ctx->window.stats_win;
    const netos_pktdump_stats_t *s = &ctx->stats;

    /* Clear the inner stats window only. The border container is drawn separately. */
    werase(w);

    /* Interface & Time stats (offset inside inner window starts at y=0, x=1) */
    double elapsed = ui_elapsed_seconds(s);
    double pps     = (elapsed > 0.0) ? ((double)s->rx_pkts / elapsed) : 0.0;
    char bytes_str[32];
    ui_fmt_bytes(s->rx_bytes, bytes_str, sizeof(bytes_str));

    mvwprintw(w, 0, 1, "Interface: %-10s  |  Elapsed: %.1f s  |  Pkt/s: %.1f  |  Total Pkts: %-8" PRIu64 "  |  Total Data: ",
              ctx->ifname ? ctx->ifname : "?", elapsed, pps, s->rx_pkts);

    /* Total data value shown in green color */
    if (has_colors()) {
        wattron(w, COLOR_PAIR(COLOR_PAIR_GREEN) | A_BOLD);
        wprintw(w, "%s", bytes_str);
        wattroff(w, COLOR_PAIR(COLOR_PAIR_GREEN) | A_BOLD);
    } else {
        wprintw(w, "%s", bytes_str);
    }

    /* Protocol stats split into two rows to prevent line wrap on standard 80-column screens */
    mvwprintw(w, 1, 1, "Protocols: ");

    /* Row 1 protocols */
    const char *names1[] = {"IPv4", "TCP", "UDP", "ICMP"};
    uint64_t    vals1[]  = {s->ipv4, s->tcp, s->udp, s->icmp};
    int         num1 = sizeof(names1) / sizeof(names1[0]);

    for (int i = 0; i < num1; i++) {
        if (has_colors()) {
            wattron(w, COLOR_PAIR(COLOR_PAIR_BLUE));
        }
        wprintw(w, "%s", names1[i]);
        if (has_colors()) {
            wattroff(w, COLOR_PAIR(COLOR_PAIR_BLUE));
        }
        wprintw(w, ": %-6" PRIu64 " | ", vals1[i]);
    }

    /* Row 2 protocols */
    mvwprintw(w, 2, 1, "           ");

    const char *names2[] = {"IPv6", "ICMPv6", "ARP"};
    uint64_t    vals2[]  = {s->ipv6, s->icmp6, s->arp};
    int         num2 = sizeof(names2) / sizeof(names2[0]);

    for (int i = 0; i < num2; i++) {
        if (has_colors()) {
            wattron(w, COLOR_PAIR(COLOR_PAIR_BLUE));
        }
        wprintw(w, "%s", names2[i]);
        if (has_colors()) {
            wattroff(w, COLOR_PAIR(COLOR_PAIR_BLUE));
        }
        wprintw(w, ": %-6" PRIu64 " | ", vals2[i]);
    }

    /* "Other" highlighted in red (both label and count) at the end of Row 2 */
    if (has_colors()) {
        wattron(w, COLOR_PAIR(COLOR_PAIR_RED) | A_BOLD);
        wprintw(w, "Other: %" PRIu64, s->other);
        wattroff(w, COLOR_PAIR(COLOR_PAIR_RED) | A_BOLD);
    } else {
        wprintw(w, "Other: %" PRIu64, s->other);
    }

    /* Stage window updates. */
    wnoutrefresh(ctx->window.packet_win);
    wnoutrefresh(w);

    /* Push all accumulated updates to physical terminal in a single operation */
    doupdate();
}

void netos_pktdump_ui_cleanup(netos_pktdump_ctx_t *ctx)
{
    if (ctx->window.packet_win) {
        scrollok(ctx->window.packet_win, FALSE);
        wprintw(ctx->window.packet_win, "\n[capture stopped]\n");
        wnoutrefresh(ctx->window.packet_win);
    }
    if (ctx->window.stats_win) {
        wnoutrefresh(ctx->window.stats_win);
    }
    doupdate();

    if (ctx->window.top_win)           { delwin(ctx->window.top_win);           }
    if (ctx->window.packet_win)        { delwin(ctx->window.packet_win);        }
    if (ctx->window.packet_border_win) { delwin(ctx->window.packet_border_win); }
    if (ctx->window.stats_border_win)  { delwin(ctx->window.stats_border_win);  }
    if (ctx->window.stats_win)         { delwin(ctx->window.stats_win);         }

    endwin();
}
