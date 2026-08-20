#include <stdint.h>
#include "netos_status.h"
#include "netos_log.h"
#include "pkt_buffer.h"
#include "raw_socket.h"
#include "arp_hdr.h"
#include "eth.h"
#include "ethertypes.h"
#include "protocol_const.h"
#include "common.h"

typedef struct netos_arp_entry {
    char        ifname[15];
    uint8_t     sender_mac[6];
    uint32_t    sender_ip;
    struct netos_arp_entry *next;
} netos_arp_entry_t;

static netos_arp_entry_t *entries;
static netos_arp_entry_t *tail;

static bool __pgen_find_arp_entry(netos_arp_hdr_t *arp_hdr,
                                  netos_eth_hdr_t *eh)
{
    if (!entries) {
        return false;
    }

    netos_arp_entry_t *entry;
    for (entry = entries; entry; entry = entry->next) {
        if (!memcmp(eh->src, entry->sender_mac, NETOS_MACADDR_LEN)) {
            uint32_t ipaddr = 0;

            if ((arp_hdr->op == NETOS_ARP_OP_REQUEST) ||
                (arp_hdr->op == NETOS_ARP_OP_REPLY)) {
                ipaddr = arp_hdr->sender_protocol_addr;
            }
            if (entry->sender_ip == ipaddr) {
                return true;
            }
        }
    }

    return false;
}

static void __pgen_print_arp_entries()
{
    netos_arp_entry_t *entry;

    netos_log_info("ifname\t sender_mac\t    sender_ip\n");
    netos_log_info("-----------------------------------------\n");
    for (entry = entries; entry; entry = entry->next) {
        netos_log_info("<%s>\t <%02x:%02x:%02x:%02x:%02x:%02x> <%d.%d.%d.%d>\n",
                       entry->ifname,
                       entry->sender_mac[0], entry->sender_mac[1],
                       entry->sender_mac[2], entry->sender_mac[3],
                       entry->sender_mac[4], entry->sender_mac[5],
                       (entry->sender_ip & 0xFF000000) >> 24,
                       (entry->sender_ip & 0x00FF0000) >> 16,
                       (entry->sender_ip & 0x0000FF00) >> 8,
                       (entry->sender_ip & 0x000000FF));
    }
    netos_log_info("-----------------------------------------\n");
}

static void __pgen_arp_add_entry(const char *ifname,
                                 netos_arp_hdr_t *arp_hdr,
                                 netos_eth_hdr_t *eh)
{
    netos_arp_entry_t *entry;
    bool valid_entry;

    // ignore sender's broadcast mac address
    if (netos_is_broadcast_mac(eh->src) ||
        netos_is_broadcast_mac(arp_hdr->sender_hwaddr)) {
        return;
    }

    valid_entry = __pgen_find_arp_entry(arp_hdr, eh);
    if (!valid_entry) {
        entry = calloc(1, sizeof(netos_arp_entry_t));
        if (!entry) {
            return;
        }

        strcpy(entry->ifname, ifname);
        memcpy(entry->sender_mac, eh->src, NETOS_MACADDR_LEN);

        if ((arp_hdr->op == NETOS_ARP_OP_REQUEST) ||
            (arp_hdr->op == NETOS_ARP_OP_REPLY)) {
            entry->sender_ip = arp_hdr->sender_protocol_addr;
        }

        if (!entries) {
            entries = entry;
            tail = entry;
        } else {
            tail->next = entry;
            tail = entry;
        }
    }

    __pgen_print_arp_entries();
}

static void __pgen_arp_listen(const char *ifname, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;

    netos_eth_hdr_t eh;
    netos_arp_hdr_t arp_hdr;

    ret= netos_eth_decode(&eh, pkt_buf);
    if (ret == NETOS_STATUS_SUCCESS) {
        ret = netos_arp_decode(&arp_hdr, pkt_buf);
        if (ret == NETOS_STATUS_SUCCESS) {
            __pgen_arp_add_entry(ifname, &arp_hdr, &eh);
        }
    }
}

void pgen_arp_listen(netos_raw_socket_ctx_t *raw, void *config)
{
    while (1) {
        pkt_buffer_t rx_buf;
        int ret;

        memset(&rx_buf, 0, sizeof(rx_buf));

        ret = netos_raw_socket_rx_ethertype(raw,
                                            rx_buf.buffer,
                                            NETOS_PKT_BUFFER_LEN,
                                            NETOS_ETHERTYPE_ARP);
        if (ret < 0) {
            netos_log_error("failed to recvfrom\n");
            return;
        } else if (ret > 0) {
            rx_buf.rx_len = ret; // set rx frame length to decode
            // ARP frame
            __pgen_arp_listen(raw->ifname, &rx_buf);
        }
    }
}

