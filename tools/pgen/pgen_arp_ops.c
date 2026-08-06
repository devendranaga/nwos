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
            netos_arp_print(&arp_hdr);
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

