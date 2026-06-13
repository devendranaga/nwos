#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "arp.h"
#include "netos_log.h"
#include "network_config.h"
#include "network_main.h"

static void netos_usage(const char *progname)
{
    fprintf(stderr, "NetOS Daemon <%s> -f <config file>\n", progname);
}

static netos_status_t netos_parse_cmdargs(int argc, char **argv, netos_cmdargs_t *cmdargs)
{
    int ret;

    while ((ret = getopt(argc, argv, "f:")) != -1) {
        switch (ret) {
            case 'f':
                cmdargs->config_file = strdup(optarg);
            break;
            default:
                netos_usage(argv[0]);
                return -1;
        }
    }

    return NETOS_STATUS_SUCCESS;
}

static void *netos_intf_rx_callback(void *cbdata)
{
    netos_intf_t *intf = cbdata;
    int ret;

    netos_log_info("Rx thread for [%s] ready\n", intf->ifname);

    while (1) {
        pkt_buffer_t *rx_buf = netos_buffer_pool_get_buffer(intf->rx_pool);
        if (!rx_buf) {
            //netos_log_warn("Out of rx buffers.. retry\n");
            continue;
        }

        rx_buf->in_intf = intf->raw;

        ret = netos_raw_socket_rx(intf->raw, rx_buf->buffer, sizeof(rx_buf->buffer));
        if (ret < 0) {
            continue;
        }

        clock_gettime(CLOCK_REALTIME, &rx_buf->rx_ts);
        rx_buf->rx_len = ret;

        pthread_mutex_lock(&intf->parser_thr->parse_q_lock);
        pkt_buffer_ref_count_up(rx_buf);
        netos_queue_push(intf->parser_thr->parse_q, rx_buf);
        pthread_cond_signal(&intf->parser_thr->parse_q_cond);
        pthread_mutex_unlock(&intf->parser_thr->parse_q_lock);
    }

    return NULL;
}

static void netos_update_rx_event(const char *ifname, pkt_buffer_t *pkt_buf)
{
    netos_event_info_t *evt_info;

    evt_info = netos_event_mgr_get_evt_buf();
    if (!evt_info) {
        netos_log_error("No available event buffers\n");
        return;
    }

    NETOS_EVENT_INFO_CREATE(evt_info,
                            ifname,
                            pkt_buf->rx_ts.tv_sec,
                            pkt_buf->rx_ts.tv_nsec,
                            pkt_buf->event_type,
                            pkt_buf->event_desc,
                            pkt_buf->rx_len);

    netos_event_mgr_add_event(evt_info);
}

static void *netos_intf_parse_callback(void *cbdata)
{
    netos_parser_thread_t *parse_thr = cbdata;
    netos_status_t ret;

    parse_thr->protocol_ctx.parsed_data.this_thread = parse_thr;

    netos_log_info("Parse callback started\n");

    while (1) {
        pthread_mutex_lock(&parse_thr->parse_q_lock);

        pkt_buffer_t *pkt;
        int length = parse_thr->parse_q->length;

        if (length > 0) {
            // retrieve the rx from the head of the queue
            pkt = netos_queue_pop(parse_thr->parse_q);

            // stats increment
            parse_thr->if_stats.in_rx_bytes += pkt->rx_len;

            // parse the frame
            ret = netos_parse_frame(pkt, &parse_thr->protocol_ctx.parsed_data);
            if (ret != NETOS_STATUS_SUCCESS) {
                netos_update_rx_event(parse_thr->ifname, pkt);
                parse_thr->if_stats.in_rx_invalid ++;
            }

        } else {
            pthread_cond_wait(&parse_thr->parse_q_cond, &parse_thr->parse_q_lock);
        }

        pthread_mutex_unlock(&parse_thr->parse_q_lock);
    }

    return NULL;
}

static netos_intf_t *netos_initialize_interface(network_if_config_t *intf_config)
{
    netos_intf_t *intf;
    netos_status_t ret;

    intf = calloc(1, sizeof(netos_intf_t));
    if (!intf) {
        return NULL;
    }

    intf->ifname = strdup(intf_config->ifname);

    intf->raw = netos_raw_socket_init(intf_config->ifname);
    if (!intf->raw) {
        goto err;
    }

    netos_log_info("raw socket on [%s] create ok\n", intf_config->ifname);

    intf->rx_pool = netos_buffer_pool_alloc(1024);
    if (!intf->rx_pool) {
        netos_log_error("Failed to allocate rx buffer pool\n");
        goto err;
    }

    netos_log_info("rx pool created ok\n");

    intf->parser_thr = calloc(1, sizeof(netos_parser_thread_t));
    if (!intf->parser_thr) {
        netos_log_error("Failed to allocate parser thread context\n");
        goto err;
    }

    intf->parser_thr->ifname = strdup(intf_config->ifname);
    intf->parser_thr->raw = intf->raw;
    intf->parser_thr->parse_q = netos_queue_init();

    netos_log_info("Initialize parse queue\n");

    pthread_mutex_init(&intf->parser_thr->parse_q_lock, NULL);
    pthread_cond_init(&intf->parser_thr->parse_q_cond, NULL);

    // initialize egress controller for this interface
    intf->egress_ctrl = netos_egress_controller_init(intf->raw);
    if (!intf->egress_ctrl) {
        netos_log_error("Failed to initialize egress controller\n");
        goto err;
    }

    netos_log_info("Initialize egress controller ok\n");

    intf->next = NULL;

    // create parse thread
    ret = netos_pthread_create_detached(&intf->parser_thr->tid, netos_intf_parse_callback, intf->parser_thr);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("failed to create rx parse thread\n");
        goto err;
    }

    netos_log_info("Created rx parse thread\n");

    // create receive thread
    ret = netos_pthread_create_detached(&intf->rx_thread, netos_intf_rx_callback, intf);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("failed to create rx thread on [%s]\n", intf->ifname);
        goto err;
    }

    netos_log_info("Created rx thread on interface [%s]\n", intf->ifname);

    return intf;

err:
    if (intf) {
        if (intf->egress_ctrl) {
            netos_egress_controller_deinit(intf->egress_ctrl);
        }
        if (intf->parser_thr) {
            if (intf->parser_thr->ifname) {
                free(intf->parser_thr->ifname);
            }
            free(intf->parser_thr);
        }
        if (intf->rx_pool) {
            netos_buffer_pool_free(intf->rx_pool);
        }
        if (intf->ifname) {
            free(intf->ifname);
        }
        free(intf);
    }

    return NULL;
}

static netos_status_t netos_initialize_protocols()
{
    netos_status_t ret;

    ret = netos_arp_protocol_init();
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_initialize_interfaces(netos_ctx_t *ctx)
{
    netos_status_t ret;
    uint32_t i;

    ret = netos_initialize_protocols();
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    for (i = 0; i < ctx->config.n_if_config; i ++) {
        netos_intf_t *intf;

        intf = netos_initialize_interface(&ctx->config.if_config[i]);
        if (!intf) {
            return NETOS_STATUS_MEMORY_ALLOC_FAILURE;
        }

        if (!ctx->interfaces) {
            ctx->interfaces = intf;
        } else {
            intf->next = ctx->interfaces;
            ctx->interfaces = intf;
        }

        netos_log_info("Interface [%s] initialized ok\n", ctx->config.if_config[i].ifname);
    }

    return NETOS_STATUS_SUCCESS;
}

int main(int argc, char **argv)
{
    netos_ctx_t *ctx;
    int ret;

    ctx = calloc(1, sizeof(netos_ctx_t));
    if (!ctx) {
        return -1;
    }

    ret = netos_parse_cmdargs(argc, argv, &ctx->cmdargs);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    netos_log_info("Parse command line arguments ok\n");

    ret = netos_config_parse(&ctx->config, ctx->cmdargs.config_file);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("Config parse failure error : %x\n", ret);
        return ret;
    }

    netos_log_info("Config parse ok\n");
    netos_config_print(&ctx->config);

    // initialize event manager
    ret = netos_event_mgr_init();
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("Cannot initialize event manager\n");
        return ret;
    }

    ret = netos_initialize_interfaces(ctx);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("Interface list initialization failed error : %x\n", ret);
        return ret;
    }

    while (1) {
        sleep(1);
    }

    return ret;
}
