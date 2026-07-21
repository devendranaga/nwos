#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "arp.h"
#include "ipv4.h"
#include "netos_log.h"
#include "netos_config.h"
#include "cpu_affinity.h"
#include "perf_intf.h"
#include "netos_main.h"

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
        pkt_buffer_t *rx_buf = netos_buffer_pool_get_buffer(intf->parser_thr->rx_pool);
        if (!rx_buf) {
            //netos_log_warn("Out of rx buffers.. retry\n");
            continue;
        }

        NETOS_PERF_EVENT_INITIALIZE(rx_buf->perf_evt);

        NETOS_PERF_EVENT_START(rx_buf->perf_evt);

        rx_buf->event_type = NETOS_EVENT_TYPE_INVAL;
        rx_buf->event_desc = NETOS_EVENT_DESC_INVAL;

        rx_buf->in_intf = intf->raw;

        ret = netos_raw_socket_rx(intf->raw, rx_buf->buffer, sizeof(rx_buf->buffer));
        if (ret <= 0) {
            // receive failed, give back the buffer to the pool
            netos_buffer_pool_put_buffer(intf->parser_thr->rx_pool, rx_buf);
            continue;
        }

        clock_gettime(CLOCK_REALTIME, &rx_buf->rx_ts);
        rx_buf->rx_len = ret;
        intf->parser_thr->if_stats.in_rx_bytes += ret;

        pthread_mutex_lock(&intf->parser_thr->parse_q_lock);
        pkt_buffer_ref_count_up(rx_buf);
        netos_ring_add(&intf->parser_thr->parse_ring, rx_buf);
        pthread_cond_signal(&intf->parser_thr->parse_q_cond);
        pthread_mutex_unlock(&intf->parser_thr->parse_q_lock);
    }

    return NULL;
}

static void netos_update_rx_event(const char *ifname, pkt_buffer_t *pkt_buf)
{
    netos_event_info_t *evt_info;

    if ((pkt_buf->event_type == NETOS_EVENT_TYPE_INVAL) ||
        (pkt_buf->event_desc == NETOS_EVENT_DESC_INVAL)) {
        return;
    }

    // all the new events will be dropped if we do not have a free buffer
    evt_info = netos_event_mgr_get_evt_buf();
    if (!evt_info) {
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
    bool ring_empty;
    netos_parser_thread_t *parse_thr = cbdata;
    netos_status_t ret;

    parse_thr->protocol_ctx.parsed_data.this_thread = parse_thr;

    netos_log_info("Parse callback started\n");

    while (1) {
        pthread_mutex_lock(&parse_thr->parse_q_lock);

        pkt_buffer_t *pkt;

        // if ring is empty wait for the signal from the rx thread
        ring_empty = NETOS_RING_EMPTY(parse_thr->parse_ring);

        if (!ring_empty) {
            // retrieve the rx from the head of the queue
            pkt = netos_ring_remove(&parse_thr->parse_ring);

            // once the pkt is removed from the ring, there is no need to
            // held the lock to perform parsing on the pkt
            pthread_mutex_unlock(&parse_thr->parse_q_lock);
            if (!pkt) {
                continue;
            }

            // parse the frame
            ret = netos_parse_frame(pkt, &parse_thr->protocol_ctx.parsed_data);
            if (ret != NETOS_STATUS_SUCCESS) {
                netos_update_rx_event(parse_thr->ifname, pkt);
                netos_buffer_pool_put_buffer(parse_thr->rx_pool, pkt);
                parse_thr->if_stats.in_rx_invalid ++;
            }
            NETOS_PERF_EVENT_END(pkt->perf_evt);

        } else {
            // wait until atleast one item is in ring
            pthread_cond_wait(&parse_thr->parse_q_cond, &parse_thr->parse_q_lock);
            pthread_mutex_unlock(&parse_thr->parse_q_lock);
        }
    }

    return NULL;
}

static netos_intf_t *netos_initialize_interface(network_if_config_t *intf_config,
                                                network_config_t *config)
{
    netos_intf_t *intf;
    netos_status_t ret;

    intf = calloc(1, sizeof(netos_intf_t));
    if (!intf) {
        netos_log_error("failed to initialize the interface\n");
        return NULL;
    }

    intf->ifname = strdup(intf_config->ifname);

    // initialize the raw socket.. probably doing raw socket is
    // not a  bright idea, but could do better interface someday.
    intf->raw = netos_raw_socket_init(intf_config->ifname);
    if (!intf->raw) {
        netos_log_error("failed to initialize the raw socket\n");
        goto err;
    }

    netos_log_info("raw socket on [%s] create ok\n", intf_config->ifname);

    netos_log_info("rx pool created ok\n");

    intf->parser_thr = calloc(1, sizeof(netos_parser_thread_t));
    if (!intf->parser_thr) {
        netos_log_error("Failed to allocate parser thread context\n");
        goto err;
    }

    intf->parser_thr->rx_pool = netos_buffer_pool_alloc(config->rx_pkt_buffer_pool_len);
    if (!intf->parser_thr->rx_pool) {
        netos_log_error("Failed to allocate rx buffer pool\n");
        goto err;
    }

    intf->parser_thr->ifname = strdup(intf_config->ifname);
    intf->parser_thr->raw = intf->raw;
    netos_ring_init(&intf->parser_thr->parse_ring, 1024);

    netos_log_info("Initialize parse queue\n");

    pthread_mutex_init(&intf->parser_thr->parse_q_lock, NULL);
    pthread_cond_init(&intf->parser_thr->parse_q_cond, NULL);

    // initialize egress controller for this interface
    intf->raw->egress_ctrl = netos_egress_controller_init(intf->raw, config);
    if (!intf->raw->egress_ctrl) {
        netos_log_error("Failed to initialize egress controller\n");
        goto err;
    }

    netos_log_info("Initialize egress controller ok\n");

    intf->next = NULL;

    // create parse thread
    ret = netos_pthread_create_detached(&intf->parser_thr->tid, 1, netos_intf_parse_callback, intf->parser_thr);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("failed to create rx parse thread\n");
        goto err;
    }

    netos_log_info("Created rx parse thread\n");

    // create receive thread
    ret = netos_pthread_create_detached(&intf->rx_thread, 0, netos_intf_rx_callback, intf);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("failed to create rx thread on [%s]\n", intf->ifname);
        goto err;
    }

    netos_log_info("Created rx thread on interface [%s]\n", intf->ifname);

    return intf;

err:
    if (intf) {
        if (intf->raw->egress_ctrl) {
            netos_egress_controller_deinit(intf->raw->egress_ctrl);
        }
        if (intf->parser_thr) {
            if (intf->parser_thr->rx_pool) {
                netos_buffer_pool_free(intf->parser_thr->rx_pool);
            }
            if (intf->parser_thr->ifname) {
                free(intf->parser_thr->ifname);
            }
            free(intf->parser_thr);
        }
        if (intf->ifname) {
            free(intf->ifname);
        }
        free(intf);
    }

    return NULL;
}

/**
 * @brief - Initialize protocols.
 *
 * @param [in] config - netos configuration.
 * @param [in] gcd - netos gcd context.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
static netos_status_t netos_initialize_protocols(network_config_t *config,
                                                 netos_gcd_ctx_t *gcd_ctx)
{
    netos_status_t ret;

    // initialize the ARP protocol
    ret = netos_arp_protocol_init(config, gcd_ctx);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    netos_log_info("ARP initialized\n");

    // initialize the IPv4 protocol
    ret = netos_ipv4_initialize(config);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    netos_log_info("IPv4 initialized\n");

    return NETOS_STATUS_SUCCESS;
}

/**
 * @brief - initialize network interfaces.
 *
 * @param [in] ctx - netos context.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
static netos_status_t netos_initialize_interfaces(netos_ctx_t *ctx)
{
    uint32_t i;

    for (i = 0; i < ctx->config.n_if_config; i ++) {
        netos_intf_t *intf;

        // initialize interface
        intf = netos_initialize_interface(&ctx->config.if_config[i],
                                          &ctx->config);
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

    // parse command line arguments
    ret = netos_parse_cmdargs(argc, argv, &ctx->cmdargs);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    netos_log_info("Parse command line arguments ok\n");

    // parse config file
    ret = netos_config_parse(&ctx->config, ctx->cmdargs.config_file);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("Config parse failure error : %x\n", ret);
        return ret;
    }

    // initialize the GCD context
    ctx->gcd_ctx = netos_gcd_ctx_init();
    if (!ctx->gcd_ctx) {
        netos_log_error("Initializing GCD context failed\n");
        return NETOS_STATUS_GENERIC_ERROR;
    }

    netos_log_info("Config parse ok\n");

    // initialize event manager
    ret = netos_event_mgr_init(ctx->gcd_ctx);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("Cannot initialize event manager\n");
        return ret;
    }

    // initialize all the protocols
    ret = netos_initialize_protocols(&ctx->config, ctx->gcd_ctx);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("failed to initialize protocols\n");
        return ret;
    }

    // initialize netos interfaces
    ret = netos_initialize_interfaces(ctx);
    if (ret != NETOS_STATUS_SUCCESS) {
        netos_log_error("Interface list initialization failed error : %x\n", ret);
        return ret;
    }

    // run the gcd
    netos_gcd_run(ctx->gcd_ctx);

    return ret;
}

