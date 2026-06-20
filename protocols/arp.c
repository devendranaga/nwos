#include <stdint.h>
#include <stdio.h>

#include "protocol_const.h"
#include "netos_status.h"
#include "netos_log.h"
#include "arp.h"
#include "eth.h"
#include "event_info.h"
#include "packet_parser.h"
#include "ethertypes.h"
#include "common.h"
#include "egress_controller.h"
#include "netos_config.h"

static netos_arp_protocol_t arp_protocol;

static netos_status_t netos_arp_send_reply(pkt_buffer_t *pkt_buf,
                                           netos_packet_parser_t *pkt_parser)
{
    netos_arp_hdr_t arp_h;
    netos_eth_hdr_t eth_h;

    NETOS_ETH_DEFAULTS(eth_h,
                       pkt_parser->eh.dst,
                       pkt_parser->eh.src,
                       NETOS_ETHERTYPE_ARP);

    NETOS_ARP_REPLY_DEFAULTS((&arp_h),
                             pkt_buf->in_intf->mac,
                             pkt_buf->in_intf->ipaddr,
                             pkt_parser->arp_hdr.sender_hwaddr,
                             pkt_parser->arp_hdr.sender_protocol_addr);

    pkt_buffer_reset(pkt_buf);
    pkt_buffer_set_egress_intf_self(pkt_buf);

    netos_eth_encode(&eth_h, pkt_buf);
    netos_arp_encode(&arp_h, pkt_buf);

    pkt_buffer_set_tx_len_default(pkt_buf);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_arp_rx_process_request(pkt_buffer_t *pkt_buf,
                                                   netos_packet_parser_t *pkt_parser)
{
    netos_status_t ret;

    // target hardware is us and its ARP Request
    if ((pkt_parser->arp_hdr.op == NETOS_ARP_OP_REQUEST) &&
        (pkt_parser->arp_hdr.target_protocol_addr == pkt_buf->in_intf->ipaddr)) {
        ret = netos_arp_send_reply(pkt_buf, pkt_parser);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }
    }

    return NETOS_STATUS_SUCCESS;
}

void netos_arp_mib_in_arp_ok()
{
    arp_protocol.mib.in_arp ++;
}

void netos_arp_mib_in_arp_invalid()
{
    arp_protocol.mib.in_arp_invalid ++;
}

netos_status_t netos_arp_rx_process(pkt_buffer_t *pkt_buf,
                                    netos_packet_parser_t *pkt_parser)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    pthread_mutex_lock(&arp_protocol.lock);

    // if ARP's sender hwaddr does not match with the ethernet SA
    // drop the frame
    if (memcmp(pkt_parser->arp_hdr.sender_hwaddr,
               pkt_parser->eh.src, NETOS_MACADDR_LEN) != 0) {
        ret = NETOS_STATUS_ARP_MALFORMED_PKT;
        goto unlock;
    }

    // if there is an ARP reply process it
    if (pkt_parser->arp_hdr.op == NETOS_ARP_OP_REPLY) {
        ret = netos_arp_rx_process_request(pkt_buf, pkt_parser);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto unlock;
        }
    }

    // if sender's protocol address is known, add it. be it ARP request or reply
    // sometimes there can be gratitous ARPs that contain the ip address.
    if (pkt_parser->arp_hdr.sender_protocol_addr != 0) {
        netos_arp_entry_t *entry = netos_hash_item_find(arp_protocol.arp_cache,
                                                        &pkt_parser->arp_hdr.sender_protocol_addr);
        if (!entry) {
            // add the entry
            entry = calloc(1, sizeof(netos_arp_entry_t));
            if (!entry) {
                goto unlock;
            }

            uint32_t *sender_protocol_addr = calloc(1, sizeof(uint32_t));
            if (!sender_protocol_addr) {
                ret = NETOS_STATUS_MEMORY_ALLOC_FAILURE;
                goto unlock;
            }

            *sender_protocol_addr = pkt_parser->arp_hdr.sender_protocol_addr;

            if (pkt_parser->arp_hdr.sender_protocol_addr != 0) {
                memcpy(entry->mac, pkt_parser->eh.src, NETOS_MACADDR_LEN);
                entry->in_intf = pkt_buf->in_intf;
                entry->ipaddr = pkt_parser->arp_hdr.sender_protocol_addr;
                clock_gettime(CLOCK_REALTIME, &entry->last_updated);

                netos_hash_item_add(arp_protocol.arp_cache,
                                    sender_protocol_addr,
                                    entry);
            }
        } else {
            // update it
            clock_gettime(CLOCK_REALTIME, &entry->last_updated);
        }
    }

unlock:
    pthread_mutex_unlock(&arp_protocol.lock);

    return ret;
}

static uint32_t netos_arp_entry_hash(void *key)
{
    uint32_t *ipaddr = key;
    uint32_t hash_val;

    hash_val = (((*ipaddr) & 0xFF000000) >> 24) +
               (((*ipaddr) & 0x00FF0000) >> 16) +
               (((*ipaddr) & 0x0000FF00) >> 8) +
               ((*ipaddr) & 0x000000FF);

    return hash_val;
}

static bool netos_arp_entry_compare(void *key1, void *key2)
{
    uint32_t *ipaddr1 = key1;
    uint32_t *ipaddr2 = key2;

    return *ipaddr1 == *ipaddr2;
}

static bool arp_cache_entry_invalidate(void *key, void *val)
{
    free(key); // ipaddr
    free(val); // arp_entry

    return true;
}

static void arp_do_request(netos_arp_entry_t *entry)
{
    netos_eth_hdr_t eh;
    netos_arp_hdr_t arp_h;
    const uint8_t da[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    pkt_buffer_t *pkt_buf;

    pkt_buf = netos_buffer_pool_get_buffer(arp_protocol.pool);
    if (!pkt_buf) {
        return;
    }

    NETOS_ARP_REQ_DEFAULTS((&arp_h),
                           entry->in_intf->mac,
                           entry->in_intf->ipaddr,
                           da,
                           entry->ipaddr);

    NETOS_ETH_DEFAULTS(eh,
                       da,
                       entry->in_intf->mac,
                       NETOS_ETHERTYPE_ARP);

    pkt_buf->out_intf = entry->in_intf;

    netos_eth_encode(&eh, pkt_buf);
    netos_arp_encode(&arp_h, pkt_buf);

    netos_egress_enque(entry->in_intf->egress_ctrl,
                       NETOS_EGRESS_ALG_RR,
                       pkt_buf);
}

static bool arp_cache_invalidate(void *ctx, void *key, void *val)
{
    uint32_t *ipaddr = key;
    netos_arp_entry_t *entry = val;
    struct timespec cur;
    uint64_t delta;
    uint32_t cache_invalidation_sec = 30;

    clock_gettime(CLOCK_REALTIME, &cur);
    NETOS_TIMESPEC_DELTA(cur, entry->last_updated, delta);

    // perform repeated ARP requests until the entry is purged
    if (delta > cache_invalidation_sec) {
        arp_do_request(entry);
    }

    // purge the entry
    if (delta > (cache_invalidation_sec * 3)) {
        netos_hash_item_del(arp_protocol.arp_cache, ipaddr, arp_cache_entry_invalidate);
        return true;
    }

    return false;
}

static void netos_arp_cache_timer(void *ctx)
{
    pthread_mutex_lock(&arp_protocol.lock);
    netos_hash_item_for_each(arp_protocol.arp_cache, NULL, arp_cache_invalidate);
    pthread_mutex_unlock(&arp_protocol.lock);
}

netos_status_t netos_arp_protocol_init(network_config_t *config,
                                       netos_gcd_ctx_t *gcd_ctx)
{
    netos_status_t ret;

    memset(&arp_protocol, 0, sizeof(arp_protocol));

    arp_protocol.config = config;

    // allocate 32 pkt buffer pools for ARP
    arp_protocol.pool = netos_buffer_pool_alloc(32);
    if (!arp_protocol.pool) {
        ret = NETOS_STATUS_MEMORY_ALLOC_FAILURE;
        goto err;
    }

    arp_protocol.arp_cache = netos_hash_table_init(
                                        config->protocol_config.arp_config.arp_cache_size,
                                        netos_arp_entry_hash,
                                        netos_arp_entry_compare);
    if (!arp_protocol.arp_cache) {
        ret = NETOS_STATUS_HASH_TABLE_ALLOC_FAILURE;
        goto err;
    }

    netos_log_info("create arp cache ok\n");

    netos_gcd_timer_set_callback(gcd_ctx,
                                 10,
                                 0,
                                 NULL,
                                 netos_arp_cache_timer);

    netos_log_info("create arp cache timer\n");

    pthread_mutex_init(&arp_protocol.lock, NULL);

    return NETOS_STATUS_SUCCESS;

err:
    if (arp_protocol.arp_cache) {
        netos_hash_table_deinit(arp_protocol.arp_cache, arp_cache_entry_invalidate);
    }

    if (arp_protocol.pool) {
        netos_buffer_pool_free(arp_protocol.pool);
    }

    return ret;
}

