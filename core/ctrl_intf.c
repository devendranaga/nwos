#include <string.h>
#include <stdlib.h>
#include "netos_status.h"
#include "gcd.h"
#include "unix_intf.h"
#include "statistics_ctx.h"
#include "ctrl_intf.h"
#include "intf_statistics.h"
#include "netctl_intf.h"
#include "netos_log.h"

static void netos_ctrl_intf_rx_command(int fd, void *user_ctx)
{
    netos_netctl_intf_t *intf_msg;
    uint8_t buf[2048];
    char path[128];
    int ret;

    netos_log_info("rx ctrl sock called\n");

    intf_msg = (netos_netctl_intf_t *)buf;

    ret = netos_unix_intf_udp_recv(fd, path, buf, sizeof(buf));
    if (ret < 0) {
        return;
    }

    switch (intf_msg->type) {
        case NETOS_NETCTL_GET_INGRESS_STATS: {
            netos_netctl_ingress_statistics_t *ingress_stats;
            uint32_t count;
            uint32_t total_send_len;

            count = netos_statistics_get_ingress_stats(buf + sizeof(netos_netctl_intf_t),
                                                       sizeof(buf) - sizeof(netos_netctl_intf_t));

            if (count != 0) {
                ingress_stats = (netos_netctl_ingress_statistics_t *)(buf + sizeof(netos_netctl_intf_t));
                netos_log_info("n_rx %lu\n", ingress_stats->n_rx);
                netos_log_info("n_arp_rx %lu\n", ingress_stats->n_arp_rx);
                netos_log_info("n_ipv4_rx %lu\n", ingress_stats->n_ipv4_rx);
                netos_log_info("n_ipv5_rx %lu\n", ingress_stats->n_ipv6_rx);
            }

            total_send_len = sizeof(netos_netctl_intf_t) + sizeof(netos_netctl_ingress_statistics_t) * count;

            netos_unix_intf_udp_send(fd, path, buf, total_send_len);

        } break;
    }
}

void *netos_ctrl_intf_init(const char *path,
                           netos_gcd_ctx_t *gcd)
{
    netos_ctrl_intf_ctx_t *ctx;

    ctx = calloc(1, sizeof(netos_ctrl_intf_ctx_t));
    if (!ctx) {
        return NULL;
    }

    ctx->path = strdup(path);
    ctx->fd = netos_unix_intf_udp_server_socket_init(path);
    if (ctx->fd < 0) {
        goto err;
    }

    netos_gcd_socket_set_callback(gcd,
                                  ctx->fd,
                                  ctx,
                                  netos_ctrl_intf_rx_command);

    netos_log_info("Ctrl_intf: initialized\n");

    return ctx;

err:
    if (ctx) {
        if (ctx->fd > 0) {
            netos_unix_intf_udp_close(ctx->fd, ctx->path);
        }
        if (ctx->path) {
            free(ctx->path);
        }
    }

    return NULL;
}

