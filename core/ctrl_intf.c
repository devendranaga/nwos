#include <string.h>
#include <stdlib.h>
#include "netos_status.h"
#include "gcd.h"
#include "unix_intf.h"
#include "unix_util.h"
#include "statistics_ctx.h"
#include "ctrl_intf.h"
#include "intf_statistics.h"
#include "netctl_intf.h"
#include "netos_log.h"

static inline void netos_ctrl_intf_send_error_resp(netos_netctl_intf_t *intf_msg,
                                                   int fd,
                                                   uint32_t status_code,
                                                   const char *path,
                                                   uint8_t *buf)
{
    NETOS_NETCTL_INTF_INIT(intf_msg, NETOS_NETCTL_STATUS);
    netos_netctl_status_t *status = (netos_netctl_status_t *)(intf_msg->val);
    uint32_t total_send_len;

    status->status_code = status_code;
    total_send_len = sizeof(netos_netctl_intf_t) + sizeof(netos_netctl_status_t);

    netos_unix_intf_udp_send(fd, path, buf, total_send_len);
}

static void netos_ctrl_intf_rx_command(int fd, void *user_ctx)
{
    netos_netctl_intf_t *intf_msg;
    uint8_t buf[2048];
    char path[128];
    int ret;

    intf_msg = (netos_netctl_intf_t *)buf;

    ret = netos_unix_intf_udp_recv(fd, path, sizeof(path), buf, sizeof(buf));
    if (ret < 0) {
        return;
    }

    if (intf_msg->version != NETOS_NETCTL_VERSION) {
        netos_ctrl_intf_send_error_resp(intf_msg,
                                        fd,
                                        NETOS_NETCTL_INVAL_VERSION,
                                        path,
                                        buf);
        return;
    }


    switch (intf_msg->type) {
        case NETOS_NETCTL_GET_INGRESS_STATS: {
            uint32_t count;
            uint32_t total_send_len;

            count = netos_statistics_get_ingress_stats(buf + sizeof(netos_netctl_intf_t),
                                                       sizeof(buf) - sizeof(netos_netctl_intf_t));

#if defined(NETOS_DEBUG)
            if (count != 0) {
                netos_netctl_ingress_statistics_t *ingress_stats;

                ingress_stats = (netos_netctl_ingress_statistics_t *)(buf + sizeof(netos_netctl_intf_t));
                netos_log_info("n_rx        %lu\n", ingress_stats->n_rx);
                netos_log_info("n_arp_rx    %lu\n", ingress_stats->n_arp_rx);
                netos_log_info("n_ipv4_rx   %lu\n", ingress_stats->n_ipv4_rx);
                netos_log_info("n_ipv6_rx   %lu\n", ingress_stats->n_ipv6_rx);
            }
#endif

            // even if count is 0, we send a response back but the netctl would
            // simply check that there are simply no statistics for the GET_INGRESS_STATS
            total_send_len = sizeof(netos_netctl_intf_t) + sizeof(netos_netctl_ingress_statistics_t) * count;

            netos_unix_intf_udp_send(fd, path, buf, total_send_len);

        } break;
        default:
            netos_ctrl_intf_send_error_resp(intf_msg,
                                            fd,
                                            NETOS_NETCTL_UNKNOWN_TYPE,
                                            path,
                                            buf);
        break;
    }
}

void *netos_ctrl_intf_init(const char *path,
                           netos_gcd_ctx_t *gcd)
{
    netos_ctrl_intf_ctx_t *ctx;

    if (netos_is_unix_socket_active(path)) {
        return NULL;
    }

    ctx = calloc(1, sizeof(netos_ctrl_intf_ctx_t));
    if (!ctx) {
        return NULL;
    }

    ctx->path = strdup(path);
    if (!ctx->path) {
        goto err;
    }

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
        if (ctx->fd >= 0) {
            netos_unix_intf_udp_close(ctx->fd, ctx->path);
        }
        if (ctx->path) {
            free(ctx->path);
        }
    }

    return NULL;
}

