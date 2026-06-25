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
#include "protocols.h"
#include "pgen.h"

static struct pgen pgen;

struct pgen_token {
    char name[40];
};

static void pgen_help(struct pgen_token *tokens, uint32_t n_tokens);

static void pgen_eth_run();
static void pgen_arp_run();
static void pgen_ipv4_run();
static void pgen_icmp_run();

static struct {
    const char  *str;
    bool        enable;
    void        (*callback)();
} pgen_run_callback_list[] = {
    {
        "eth",  false, pgen_eth_run
    },
    {
        "arp",  false, pgen_arp_run
    },
    {
        "ipv4", false, pgen_ipv4_run
    },
    {
        "icmp", false, pgen_icmp_run
    }
};

static void pgen_set_defaults()
{
    const uint8_t dst[]         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    const uint8_t src[]         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    const uint16_t ethertype    = 0x0800;
    const uint32_t src_ipaddr   = 0xc0a8000a; // 192.168.0.10
    const uint32_t dst_ipaddr   = 0xc0a80001; // 192.168.0.1

    NETOS_ETH_DEFAULTS(pgen.eth_hdr, dst, src, ethertype);

    NETOS_VLAN_DEFAULTS(pgen.vlan_hdr, 1, 1, 0, NETOS_ETHERTYPE_IPV4);

    NETOS_ARP_REQ_DEFAULTS((&pgen.arp_hdr), src, src_ipaddr, dst, dst_ipaddr);

    NETOS_IPV4_DEFAULTS(pgen.ipv4_hdr, 0, 0x1234, NETOS_PROTOCOL_TCP, src_ipaddr, dst_ipaddr);

    NETOS_ICMP_ECHO_REQ_DEFAULTS(pgen.icmp_hdr, 0x1234, 0x1234);

    // default transmit params
    pgen.ifname         = NULL;
    pgen.raw            = NULL;
    pgen.ipg_ns         = 1000 * 1000 * 100; // every 100ms
    pgen.n_frames       = 10; // 10 frames
    pgen.len            = 100; // 100 bytes
    pgen.eth_enable     = false;
    pgen.arp_enable     = false;
    pgen.ipv4_enable    = false;
}

static void set_icmp_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen.icmp_enable = true;
    pgen_run_callback_list[3].enable = true;
}

static void set_ipv4_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen.ipv4_enable = true;
    pgen_run_callback_list[2].enable = true;
}

static void set_ipv4_version(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t version;

    ret = netos_get_u32_from_str(tokens[1].name, &version);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.ipv4_hdr.version = version;
}

static void set_ipv4_src_ip(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_ipv4addr_from_str(tokens[1].name, &pgen.ipv4_hdr.src_ipaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.ipv4_hdr.src_ipaddr = ntohl(pgen.ipv4_hdr.src_ipaddr);
}

static void set_ipv4_dst_ip(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_ipv4addr_from_str(tokens[1].name, &pgen.ipv4_hdr.dst_ipaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.ipv4_hdr.dst_ipaddr = ntohl(pgen.ipv4_hdr.dst_ipaddr);
}

static void set_ipv4_ttl(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t ttl;

    ret = netos_get_u32_from_str(tokens[1].name, &ttl);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.ipv4_hdr.ttl = ttl;
}

static void set_ipv4_protocol(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t protocol;

    ret = netos_get_u32_from_str(tokens[1].name, &protocol);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.ipv4_hdr.protocol = protocol;
}

static void set_vlan_id(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t vid;

    ret = netos_get_u32_from_str(tokens[1].name, &vid);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.vlan_enable = true;
    pgen.eth_hdr.ethertype = NETOS_ETHERTYPE_VLAN;
    pgen.vlan_hdr.vlan_id = vid;
}

static void set_vlan_priority(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t priority;

    ret = netos_get_u32_from_str(tokens[1].name, &priority);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.vlan_enable = true;
    pgen.eth_hdr.ethertype = NETOS_ETHERTYPE_VLAN;
    pgen.vlan_hdr.pcp = priority;
}

static void set_vlan_next_ethertype(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_hex_from_str(tokens[1].name, &pgen.vlan_hdr.ethertype);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.vlan_enable = true;
    pgen.eth_hdr.ethertype = NETOS_ETHERTYPE_VLAN;
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
    if (pgen.vlan_enable) {
        netos_vlan_encode(&pgen.vlan_hdr, &pkt_buf);
    }
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

    if (pgen.vlan_enable) {
        pgen.vlan_hdr.ethertype = NETOS_ETHERTYPE_ARP;
        netos_vlan_encode(&pgen.vlan_hdr, &pkt_buf);
    }
    netos_arp_encode(&pgen.arp_hdr, &pkt_buf);

    if ((pgen.len != 0) && (pgen.len < sizeof(data_buf) - 80)) {
        pkt_buffer_encode_bytes(&pkt_buf, data_buf, pgen.len);
    }

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_ipv4_run()
{
    uint8_t data_buf[1024] = {0};
    pkt_buffer_t pkt_buf;

    pkt_buffer_initialize(&pkt_buf);
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);

    if (pgen.ipv4_hdr.hdr_chksum == 0) {
        pgen.ipv4_hdr.gen_checksum = true;
    }
    netos_ipv4_encode(&pgen.ipv4_hdr, &pkt_buf);

    if ((pgen.len != 0) && (pgen.len < sizeof(data_buf) - 80)) {
        pkt_buffer_encode_bytes(&pkt_buf, data_buf, pgen.len);
    }

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_icmp_run()
{
    uint8_t data_buf[1024] = {0};
    pkt_buffer_t pkt_buf;

    pkt_buffer_initialize(&pkt_buf);
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);
    pgen.ipv4_hdr.gen_checksum = true;
    pgen.ipv4_hdr.protocol = NETOS_PROTOCOL_ICMP;
    netos_ipv4_encode(&pgen.ipv4_hdr, &pkt_buf);

    pgen.icmp_hdr.checksum = 0;
    if (pgen.len == 0) {
        pgen.icmp_hdr.u.echo_req.data = NULL;
        pgen.icmp_hdr.u.echo_req.data_len = 0;
    } else {
        pgen.icmp_hdr.u.echo_req.data = data_buf;
        pgen.icmp_hdr.u.echo_req.data_len = pgen.len;
    }
    pgen.icmp_hdr.gen_checksum = true;
    netos_icmp_encode(&pgen.icmp_hdr, &pkt_buf);

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_run(struct pgen_token *tokens, uint32_t n_tokens)
{
    if (!pgen.ifname) {
        fprintf(stderr, "Interface name is not present. Interface should be provided via ifname\n");
        return;
    }

    pgen.raw = netos_raw_socket_init(pgen.ifname);
    if (!pgen.raw) {
        fprintf(stderr, "Failed to create a raw socket.. is the interface available and up?\n");
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

#define ETH_ENABLE_CMD      "eth.enable"
#define ARP_ENABLE_CMD      "arp.enable"
#define ETH_DA_CMD          "eth.da"
#define ETH_SA_CMD          "eth.sa"
#define ETH_ETHERTYPE_CMD   "eth.ethertype"
#define VLAN_ID_CMD         "vlan.id"
#define VLAN_PRIORITY_CMD   "vlan.priority"
#define VLAN_NEXT_ETHER_CMD "vlan.next_ether"
#define ARP_OP_CMD          "arp.op"
#define ARP_SHA_CMD         "arp.sha"
#define ARP_SPA_CMD         "arp.spa"
#define ARP_THA_CMD         "arp.tha"
#define ARP_TPA_CMD         "arp.tpa"
#define IPV4_ENABLE_CMD     "ipv4.enable"
#define IPV4_VERSION_CMD    "ipv4.version"
#define IPV4_SRC_IP_CMD     "ipv4.src_ipaddr"
#define IPV4_DST_IP_CMD     "ipv4.dst_ipaddr"
#define IPV4_TTL_CMD        "ipv4.ttl"
#define IPV4_PROTOCOL_CMD   "ipv4.protocol"
#define ICMP_ENABLE_CMD     "icmp.enable"
#define IPG_CMD             "ipg"
#define N_FRAMES_CMD        "n_frames"
#define LEN_CMD             "len"
#define IFNAME_CMD          "ifname"
#define RUN_CMD             "run"
#define EXIT_CMD            "exit"
#define QUIT_CMD            "quit"
#define HELP_CMD            "help"
#define ETH_ENABLE_STR      "Enables the Ethernet frame generation"
#define ARP_ENABLE_STR      "Enables the ARP frame generation"
#define ETH_DA_STR          "Set the Eth DA"
#define ETH_SA_STR          "Set the Eth SA"
#define ETH_ETHERTYPE_STR   "Set the Eth Ethertype"
#define VLAN_ID_STR         "Set the VLAN Id"
#define VLAN_PRIORITY_STR   "Set the VLAN priority"
#define VLAN_NEXT_ETHER_STR "Set the VLAN next ethertype"
#define ARP_OP_STR          "Set the ARP operation<request = 1/ reply = 2>"
#define ARP_SHA_STR         "Set the ARP's sender HW Addr"
#define ARP_SPA_STR         "Set the ARP sender Ip address"
#define ARP_THA_STR         "Set the ARP's target HW Address"
#define ARP_TPA_STR         "Set the ARP's target protocol address"
#define IPV4_VERSION_STR    "Set the IPv4 version"
#define IPV4_ENABLE_STR     "Enables the IPv4 frame generation"
#define IPV4_SRC_IP_STR     "Set the ipv4.src_ipaddr"
#define IPV4_DST_IP_STR     "Set the ipv4.dst_ipaddr"
#define IPV4_TTL_STR        "Set the IPv4 TTL"
#define IPV4_PROTOCOL_STR   "Set the IPV4 Protocol"
#define ICMP_ENABLE_STR     "Set the ICMP enable"
#define IPG_STR             "Set the Inter packet gap (in nanoseconds)"
#define N_FRAMES_STR        "Set Number of frames to send"
#define LEN_STR             "Set the packet length"
#define IFNAME_STR          "Set the interface name"
#define RUN_STR             "Run the packet generator"
#define EXIT_STR            "Exit the packet generator"
#define QUIT_STR            EXIT_STR
#define HELP_STR            "Show help"

static const struct {
    const char  *str;
    const char  *desc;
    void        (*callback)(struct pgen_token *tokens, uint32_t n_tokens);
} pgen_setup_callbacks[] = {
    { ETH_ENABLE_CMD,       ETH_ENABLE_STR,         set_eth_enable },
    { ARP_ENABLE_CMD,       ARP_ENABLE_STR,         set_arp_enable },
    { ETH_DA_CMD,           ETH_DA_STR,             set_eth_da },
    { ETH_SA_CMD,           ETH_SA_STR,             set_eth_sa },
    { ETH_ETHERTYPE_CMD,    ETH_ETHERTYPE_STR,      set_eth_ethertype },
    { VLAN_ID_CMD,          VLAN_ID_STR,            set_vlan_id },
    { VLAN_PRIORITY_CMD,    VLAN_PRIORITY_STR,      set_vlan_priority },
    { VLAN_NEXT_ETHER_CMD,  VLAN_NEXT_ETHER_STR,    set_vlan_next_ethertype },
    { ARP_OP_CMD,           ARP_OP_STR,             set_arp_op },
    { ARP_SHA_CMD,          ARP_SHA_STR,            set_arp_sha },
    { ARP_SPA_CMD,          ARP_SPA_STR,            set_arp_spa },
    { ARP_THA_CMD,          ARP_THA_STR,            set_arp_tha },
    { ARP_TPA_CMD,          ARP_TPA_STR,            set_arp_tpa },
    { IPV4_ENABLE_CMD,      IPV4_ENABLE_STR,        set_ipv4_enable },
    { IPV4_VERSION_CMD,     IPV4_VERSION_STR,       set_ipv4_version },
    { IPV4_SRC_IP_CMD,      IPV4_SRC_IP_STR,        set_ipv4_src_ip },
    { IPV4_DST_IP_CMD,      IPV4_DST_IP_STR,        set_ipv4_dst_ip },
    { IPV4_TTL_CMD,         IPV4_TTL_STR,           set_ipv4_ttl },
    { IPV4_PROTOCOL_CMD,    IPV4_PROTOCOL_STR,      set_ipv4_protocol },
    { ICMP_ENABLE_CMD,      ICMP_ENABLE_STR,        set_icmp_enable },
    { IPG_CMD,              IPG_STR,                set_ipg },
    { N_FRAMES_CMD,         N_FRAMES_STR,           set_n_frames },
    { LEN_CMD,              LEN_STR,                set_packet_len },
    { IFNAME_CMD,           IFNAME_STR,             set_ifname },
    { RUN_CMD,              RUN_STR,                pgen_run },
    { EXIT_CMD,             EXIT_STR,               pgen_exit },
    { QUIT_CMD,             QUIT_STR,               pgen_exit },
    { HELP_CMD,             HELP_STR,               pgen_help }
};

static void pgen_help(struct pgen_token *tokens, uint32_t n_tokens)
{
    uint32_t i;

    fprintf(stderr, "\n");
    for (i = 0; i < sizeof(pgen_setup_callbacks) /
                    sizeof(pgen_setup_callbacks[0]); i ++) {
        fprintf(stderr, "%-30s %s\n", pgen_setup_callbacks[i].str,
                                       pgen_setup_callbacks[i].desc);
    }
    fprintf(stderr, "\n");
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
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            continue;
        }

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

