#include <stdint.h>
#include "netos_status.h"
#include "netos_log.h"
#include "pkt_buffer.h"
#include "raw_socket.h"
#include "arp_hdr.h"
#include "eth.h"
#include "ethertypes.h"

typedef struct netos_arp_entry {
    char        ifname[15];
    uint8_t     sender_mac[6];
    uint32_t    sender_ip;
    struct netos_arp_entry *next;
} netos_arp_entry_t;

static netos_arp_entry_t *entries;

void pgen_arp_listen(netos_raw_socket_ctx_t *raw, void *config)
{
    while (1) {
        pkt_buffer_t rx_buf;
        int ret;
        netos_status_t res;

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
            netos_eth_hdr_t eh;
            netos_arp_hdr_t arp_hdr;

            res = netos_eth_decode(&eh, &rx_buf);
            if (res == NETOS_STATUS_SUCCESS) {
                ret = netos_arp_decode(&arp_hdr, &rx_buf);
                if (res == NETOS_STATUS_SUCCESS) {
                    netos_arp_print(&arp_hdr);
                    if (!entries) {
                        entries = calloc(1, sizeof(netos_arp_entry_t));
                        if (!entries) {
                            return;
                        }
                    }
                }
            }
        }
    }
}
