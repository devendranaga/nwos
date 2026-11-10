#ifndef NETOS_PROTOCOLS_ARP_API_H
#define NETOS_PROTOCOLS_ARP_API_H

typedef void (*arp_query_cb)(uint32_t query_ip, uint8_t *mac);

typedef struct netos_arp_notifier {
    arp_query_cb                query_cb;
    struct netos_arp_notifier   *next;
} netos_arp_notifier_t;

netos_status_t netos_arp_api_register_notification(arp_query_cb query_cb);

void netos_arp_api_query_ipaddr(netos_raw_socket_ctx_t *out_intf, uint32_t ipaddr);

#endif

