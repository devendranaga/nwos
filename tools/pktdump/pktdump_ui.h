#ifndef NETOS_PKTDUMP_UI_H
#define NETOS_PKTDUMP_UI_H

#include "pktdump.h"

/**
 * @brief Initialize the ncurses screen and create the three window panes.
 *
 *   - top_win   : 1-row title bar (full width, highlighted)
 *   - packet_win: scrolling packet log (content_height × 70% height)
 *   - stats_win : statistics pane    (content_height × 30% height)
 *
 * Records the capture start time in ctx->stats.start_time.
 *
 * @param ctx     Pktdump context (window handles filled in on success).
 * @param ifname  Interface name shown in the title bar.
 * @return NETOS_STATUS_SUCCESS, or NETOS_STATUS_INIT_SCREEN_FAILURE if the
 *         terminal is too small to fit the minimum layout.
 */
netos_status_t netos_pktdump_ui_init(netos_pktdump_ctx_t *ctx,
                                     const char          *ifname);

/**
 * @brief Append one decoded packet summary line to the scrolling left pane.
 *
 * Internally calls wprintw + wrefresh; ncurses scrollok() handles auto-scroll.
 *
 * @param ctx  Pktdump context.
 * @param line NUL-terminated string (no trailing newline required).
 */
void netos_pktdump_ui_append_line(netos_pktdump_ctx_t *ctx,
                                  const char          *line);

/**
 * @brief Redraw the right statistics pane with current counter values.
 *
 * Clears and redraws the right_win — call after updating ctx->stats.
 *
 * @param ctx  Pktdump context.
 */
void netos_pktdump_ui_refresh_stats(netos_pktdump_ctx_t *ctx);

/**
 * @brief Tear down all ncurses windows and restore the terminal.
 *
 * @param ctx  Pktdump context.
 */
void netos_pktdump_ui_cleanup(netos_pktdump_ctx_t *ctx);

#endif /* NETOS_PKTDUMP_UI_H */
