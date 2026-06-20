#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "netos_status.h"
#include "common.h"
#include "pkt_buffer.h"
#include "ethertypes.h"
#include "pgen.h"

static struct pgen pgen;

struct pgen_token {
    char name[40];
};

static void pgen_help(struct pgen_token *tokens, uint32_t n_tokens);

static void pgen_eth_run();
static void pgen_arp_run();

static struct {
    const char  *str;
    bool        enable;
    void        (*callback)();
} pgen_run_callback_list[] = {
    {
        "eth", false, pgen_eth_run
    },
    {
        "arp", false, pgen_arp_run
    }
};

static void pgen_set_defaults()
{
    const uint8_t dst[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    const uint8_t src[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    const uint16_t ethertype = 0x0800;
    const uint32_t src_ipaddr = 0xc0a8000a; // 192.168.0.10
    const uint32_t dst_ipaddr = 0xc0a80001; // 192.168.0.1

    NETOS_ETH_DEFAULTS(pgen.eth_hdr, dst, src, ethertype);

    NETOS_ARP_REQ_DEFAULTS((&pgen.arp_hdr), src, src_ipaddr, dst, dst_ipaddr);

    // default transmit params
    pgen.ifname     = NULL;
    pgen.raw        = NULL;
    pgen.ipg_ns     = 1000 * 1000 * 100; // every 100ms
    pgen.n_frames   = 10; // 10 frames
    pgen.len        = 100; // 100 bytes
    pgen.eth_enable = false;
    pgen.arp_enable = false;
}

static void set_eth_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen_run_callback_list[0].enable = true;
}

static void set_arp_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen_run_callback_list[1].enable = true;
}

static void set_arp_sha(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_mac_addr_from_str(tokens[1].name, pgen.arp_hdr.sender_hwaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_arp_spa(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_ipv4addr_from_str(tokens[1].name, &pgen.arp_hdr.sender_protocol_addr);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.arp_hdr.sender_protocol_addr = ntohl(pgen.arp_hdr.sender_protocol_addr);
}

static void set_arp_tha(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_mac_addr_from_str(tokens[1].name, pgen.arp_hdr.target_hwaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_arp_tpa(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_ipv4addr_from_str(tokens[1].name, &pgen.arp_hdr.target_protocol_addr);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.arp_hdr.target_protocol_addr = ntohl(pgen.arp_hdr.target_protocol_addr);
}

static void set_arp_op(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t op;

    ret = netos_get_u32_from_str(tokens[1].name, &op);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.arp_hdr.op = op;
}

static void set_eth_da(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_mac_addr_from_str(tokens[1].name, pgen.eth_hdr.dst);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_eth_sa(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_mac_addr_from_str(tokens[1].name, pgen.eth_hdr.src);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_eth_ethertype(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_hex_from_str(tokens[1].name, &pgen.eth_hdr.ethertype);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_ipg(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u64_from_str(tokens[1].name, &pgen.ipg_ns);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_n_frames(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u32_from_str(tokens[1].name, &pgen.n_frames);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_packet_len(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u32_from_str(tokens[1].name, &pgen.len);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static void set_ifname(struct pgen_token *tokens, uint32_t n_tokens)
{
    if (!pgen.ifname) {
        pgen.ifname = strdup(tokens[1].name);
    }
}

static void pgen_eth_run()
{
    pkt_buffer_t pkt_buf;
    uint8_t data_buf[1024] = {0};

    pkt_buffer_initialize(&pkt_buf);
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);
    if ((pgen.len != 0) && (pgen.len < (sizeof(data_buf) - 80))) {
        pkt_buffer_encode_bytes(&pkt_buf, data_buf, pgen.len);
    }
    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_arp_run()
{
    uint8_t data_buf[1024] = {0};
    pkt_buffer_t pkt_buf;

    pkt_buffer_initialize(&pkt_buf);
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);
    pgen.eth_hdr.ethertype = NETOS_ETHERTYPE_ARP;
    netos_arp_encode(&pgen.arp_hdr, &pkt_buf);

    if ((pgen.len != 0) && (pgen.len < sizeof(data_buf) - 80)) {
        pkt_buffer_encode_bytes(&pkt_buf, data_buf, pgen.len);
    }

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_run(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen.raw = netos_raw_socket_init(pgen.ifname);
    if (!pgen.raw) {
        return;
    }

    uint32_t i;

    void (*callback_ptr)() = NULL;

    for (i = 0; i < sizeof(pgen_run_callback_list) /
                    sizeof(pgen_run_callback_list[0]); i ++) {
        if (pgen_run_callback_list[i].enable) {
            callback_ptr = pgen_run_callback_list[i].callback;
            break;
        }
    }

    if (!callback_ptr) {
        fprintf(stderr, "no protocol generation enabled!\n");
        return;
    }

    for (i = 0; (callback_ptr) && (i < pgen.n_frames); i ++) {

        callback_ptr();

        struct timespec tp = {
            .tv_sec  = 0,
            .tv_nsec = pgen.ipg_ns,
        };

        clock_nanosleep(CLOCK_REALTIME, 0, &tp, NULL);
    }

    fprintf(stderr, "sent %d frames\n", pgen.n_frames);
}

static void pgen_exit(struct pgen_token *tokens, uint32_t n_tokens)
{
    fprintf(stderr, "exiting the pgen..\n");
    exit(1);
}

static const struct {
    const char *str;
    const char *desc;
    void (*callback)(struct pgen_token *tokens, uint32_t n_tokens);
} pgen_setup_callbacks[] = {
    {
        "eth.enable",
        "Enables the Ethernet frame generation",
        set_eth_enable,
    },
    {
        "arp.enable",
        "Enables the ARP frame generation",
        set_arp_enable,
    },
    {
        "eth.da",
        "Set the Eth DA",
        set_eth_da
    },
    {
        "eth.sa",
        "Set the Eth SA",
        set_eth_sa
    },
    {
        "eth.ethertype",
        "Set the Eth Ethertype",
        set_eth_ethertype
    },
    {
        "arp.op",
        "Set the ARP operation<request = 1/reply = 2>",
        set_arp_op
    },
    {
        "arp.sha",
        "Set the ARP's sender HW Addr",
        set_arp_sha
    },
    {
        "arp.spa",
        "Set the ARP sender Ip address",
        set_arp_spa
    },
    {
        "arp.tha",
        "Set the ARP's target HW Addr",
        set_arp_tha
    },
    {
        "arp.tpa",
        "Set the ARP's target IP addr",
        set_arp_tpa
    },
    {
        "ipg",
        "Set the inter packet gap in nanoseconds",
        set_ipg
    },
    {
        "n_frames",
        "Set Number of frames to send",
        set_n_frames
    },
    {
        "len",
        "Set packet length",
        set_packet_len,
    },
    {
        "ifname",
        "Set the interface name",
        set_ifname
    },
    {
        "run",
        "Start the packet generator",
        pgen_run
    },
    {
        "exit",
        "Exit the pgen",
        pgen_exit
    },
    {
        "help",
        "Print this help",
        pgen_help
    },
};

static void pgen_help(struct pgen_token *tokens, uint32_t n_tokens)
{
    uint32_t i;

    for (i = 0; i < sizeof(pgen_setup_callbacks) /
                    sizeof(pgen_setup_callbacks[0]); i ++) {
        fprintf(stderr, "%-18s %s\n", pgen_setup_callbacks[i].str,
                                       pgen_setup_callbacks[i].desc);
    }
}

static uint32_t pgen_tokenize(char *buf, uint32_t len, struct pgen_token *tokens)
{
    char tmp[100];
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t token_idx = 0;

    while (buf[i] != '\0') {
        if (buf[i] == ' ') {
            tmp[j] = '\0';
            strcpy(tokens[token_idx].name, tmp);
            token_idx ++;
            j = 0;
            i ++;
        } else {
            tmp[j] = buf[i];
            j ++;
            i ++;
        }
    }

    tmp[j] = '\0';
    strcpy(tokens[token_idx].name, tmp);
    token_idx ++;

    return token_idx;
}

int main(int argc, char **argv)
{
    pgen_set_defaults();

    while (1) {
        char buf[1024];

        fprintf(stderr, "pgen> ");
        fgets(buf, sizeof(buf), stdin);

        uint32_t len = strlen(buf) - 1;
        buf[len] = '\0';

        struct pgen_token tokens[10];
        uint32_t n_tokens;

        n_tokens = pgen_tokenize(buf, len, tokens);
        if (n_tokens != 0) {
            uint32_t i;

            for (i = 0; i < sizeof(pgen_setup_callbacks) /
                            sizeof(pgen_setup_callbacks[0]); i ++) {
                if (!strcmp(pgen_setup_callbacks[i].str, tokens[0].name)) {
                    pgen_setup_callbacks[i].callback(tokens, n_tokens);
                }
            }
        }
    }
    return 0;
}

