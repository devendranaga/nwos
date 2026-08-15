#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "netos_status.h"
#include "common.h"
#include "pkt_buffer.h"
#include "ethertypes.h"
#include "protocols.h"
#include "netos_log.h"
#include "pgen_arp_ops.h"
#include "pgen.h"
#include "pgen_const.h"
#include "pgen_cmd_strings.h"

static struct pgen pgen;

static void pgen_help(struct pgen_token *tokens, uint32_t n_tokens);

static void pgen_eth_run();
static void pgen_arp_run();
static void pgen_ipv4_run();
static void pgen_ipv6_run();
static void pgen_icmp_run();
static void pgen_macsec_run();
static void pgen_pcap_run();
static void *pgen_arp_fill();
static void pgen_arp_free(void *config);

/**
 * @brief - Defines a set of registered run callbacks.
 *
 * These are only called when they are enabled during the "run" command.
 */
static struct pgen_run_callback {
    const char  *str;
    const char  *desc;
    bool        enable;
    void        (*callback)();
    void        *(*fill_callback)();
    void        (*free_callback)(void *);
    void        (*listen_callback)(netos_raw_socket_ctx_t *raw, void *);
} pgen_run_callback_list[] = {
    {
        "eth",
        "Ethernet based frame generations",
        false,
        pgen_eth_run,
        NULL,
        NULL,
        NULL,
    },
    {
        "arp",
        "ARP based frame generations",
        false,
        pgen_arp_run,
        pgen_arp_fill,
        pgen_arp_free,
        pgen_arp_listen,
    },
    {
        "ipv4",
        "IPv4 based frame generations",
        false,
        pgen_ipv4_run,
        NULL,
        NULL,
        NULL,
    },
    {
        "ipv6",
        "IPv6 based frame generations",
        false,
        pgen_ipv6_run,
        NULL,
        NULL,
        NULL,
    },
    {
        "icmp",
        "ICMP based frame generations",
        false,
        pgen_icmp_run,
        NULL,
        NULL,
        NULL,
    },
    {
        "macsec",
        "MACsec based frame generations",
        false,
        pgen_macsec_run,
        NULL,
        NULL,
        NULL,
    },
    {
        "pcap",
        "Replay pcap",
        false,
        pgen_pcap_run,
        NULL,
        NULL,
        NULL,
    }
};

/**
 * @brief - set defaults for the all the headers and protocols.
 */
static void pgen_set_defaults()
{
    const uint8_t dst[]         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    const uint8_t src[]         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    const uint16_t ethertype    = 0x0800;
    const uint32_t src_ipaddr   = 0xc0a8000a; // 192.168.0.10
    const uint32_t dst_ipaddr   = 0xc0a80001; // 192.168.0.1
    const uint8_t sci[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    NETOS_ETH_DEFAULTS(pgen.eth_hdr,
                       dst,
                       src,
                       ethertype);

    NETOS_VLAN_DEFAULTS(pgen.vlan_hdr,
                        1,
                        1,
                        0,
                        NETOS_ETHERTYPE_IPV4);

    NETOS_ARP_REQ_DEFAULTS((&pgen.arp_hdr),
                           src,
                           src_ipaddr,
                           dst,
                           dst_ipaddr);

    NETOS_IPV4_DEFAULTS(pgen.ipv4_hdr,
                        0,
                        0x1234,
                        NETOS_PROTOCOL_TCP,
                        src_ipaddr,
                        dst_ipaddr);

    NETOS_ICMP_ECHO_REQ_DEFAULTS(pgen.icmp_hdr,
                                 0x1234,
                                 0x1234);

    NETOS_MACSEC_DEFAULTS(pgen.macsec_hdr,
                          0,
                          sci,
                          1,
                          0,
                          0,
                          1,
                          1,
                          0);

    NETOS_UDP_DEFAULTS(pgen.udp_hdr,
                       0,
                       0,
                       0,
                       0);

    // default transmit params
    pgen.ifname         = NULL;
    pgen.raw            = NULL;
    pgen.ipg_ns         = 1000 * 1000 * 100; // every 100ms
    pgen.n_frames       = 10; // 10 frames
    pgen.len            = 100; // 100 bytes
    pgen.eth_enable     = false;
    pgen.arp_enable     = false;
    pgen.ipv4_enable    = false;
    pgen.udp_enable     = false;
    pgen.pcap_ctx       = NULL;
    pgen.crypto_ctx     = netos_crypto_ctx_initialize();
    if (!pgen.crypto_ctx) {
        return;
    }

    pgen.gcm_ctx        = netos_crypto_init_gmac(pgen.crypto_ctx);
    if (!pgen.gcm_ctx) {
        return;
    }
}

static void set_enable_run(const char *name)
{
    uint32_t i = 0;

    for (i = 0; i < NETOS_SIZEOF_ARRAY(pgen_run_callback_list); i ++) {
        if (!strcmp(pgen_run_callback_list[i].str, name)) {
            pgen_run_callback_list[i].enable = true;
            break;
        }
    }
}

static struct pgen_run_callback *get_run_cb(const char *name)
{
    uint32_t i = 0;

    for (i = 0; i < NETOS_SIZEOF_ARRAY(pgen_run_callback_list); i ++) {
        if (!strcmp(pgen_run_callback_list[i].str, name)) {
            return pgen_run_callback_list + i;
        }
    }

    return NULL;
}

static void set_pcap_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    set_enable_run("pcap");
}

static inline void set_pcap_open_help()
{
    NETOS_PRINT_STD_GREEN_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_GREEN_COLOR("pcap.open <pcap file>\n"
                                "Ex: pcap.open macsec_replay.pcap\n");
}

static void set_pcap_open(struct pgen_token *tokens, uint32_t n_tokens)
{
    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_pcap_open_help();
        return;
    }

    if (pgen.pcap_ctx) {
        netos_pcap_close_file(pgen.pcap_ctx);
    }

    pgen.pcap_ctx = netos_pcap_read_file(tokens[1].name);
    if (!pgen.pcap_ctx) {
        NETOS_PRINT_STD_ERROR_COLOR("failed to open the pcap file for reading: %s\n",
                                    tokens[1].name);
        return;
    }

    NETOS_PRINT_STD_GREEN_COLOR("pcap file [%s] opened\n",
                                tokens[1].name);
}

static void set_macsec_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen.macsec_enable                  = true;
    set_enable_run("macsec");
}

static void set_macsec_key(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    netos_crypto_key_t key;
    FILE *key_fp;
    struct stat s;
    int res;

    res = stat(tokens[1].name, &s);
    if (res != 0) {
        NETOS_PRINT_STD_ERROR_COLOR("cannot find <%s>\n", tokens[1].name);
        return;
    }

    key_fp = fopen(tokens[1].name, "rb");
    if (!key_fp) {
        NETOS_PRINT_STD_ERROR_COLOR("cannot open <%s> for reading\n", tokens[1].name);
        return;
    }

    memset(&key, 0, sizeof(key));
    res = fread(key.key, 1, s.st_size, key_fp);
    if (res == 0) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid macsec keyfile\n");
        fclose(key_fp);
        return;
    }
    fclose(key_fp);

    if ((s.st_size != 16) && (s.st_size != 32)) {
        NETOS_PRINT_STD_ERROR_COLOR("key cannot be %ld, it must be either 16 or 32\n",
                                    s.st_size);
        return;
    }

    key.key_len = s.st_size;
    ret = netos_crypto_set_gmac_key(pgen.crypto_ctx,
                                    pgen.gcm_ctx,
                                    &key);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("failed to set key <%s>\n", tokens[1].name);
        return;
    }
}

static inline void set_macsec_encrypt_help()
{
    NETOS_PRINT_STD_GREEN_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_GREEN_COLOR("macsec.encrypt <on/off> "
                                "- turn MACsec encryption on or off\n");
}

static void set_macsec_encrypt(struct pgen_token *tokens, uint32_t n_tokens)
{
    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_encrypt_help();
        return;
    }

    if (!strcmp(tokens[1].name, "on")) {
        pgen.macsec_hdr.tci_an.e = 1;
        if (pgen.gcm_ctx) {
            netos_crypto_deinit_gmac(pgen.crypto_ctx, pgen.gcm_ctx);
        }
        pgen.gcm_ctx = netos_crypto_init_gcm(pgen.crypto_ctx);
    } else if (!strcmp(tokens[1].name, "off")) {
        pgen.macsec_hdr.tci_an.e = 0;
    } else {
        NETOS_PRINT_STD_ERROR_COLOR("invalid encrypt mode value <%s>\n",
                                    tokens[1].name);
    }
}

static inline void set_macsec_changed_help()
{
    NETOS_PRINT_STD_GREEN_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_GREEN_COLOR("macsec.changed <on/off> "
                                "- turn MACsec authentication on or off\n");
}

static void set_macsec_changed(struct pgen_token *tokens, uint32_t n_tokens)
{
    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_changed_help();
        return;
    }

    if (!strcmp(tokens[1].name, "on")) {
        pgen.macsec_hdr.tci_an.c = 1;
    } else if (!strcmp(tokens[1].name, "off")) {
        pgen.macsec_hdr.tci_an.c = 0;
    } else {
        NETOS_PRINT_STD_ERROR_COLOR("invalid changed mode value <%s>\n",
                                    tokens[1].name);
    }
}

static inline void set_macsec_es_help()
{
    NETOS_PRINT_STD_GREEN_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_GREEN_COLOR("macsec.es <on/off> - turn MACsec ES on or off\n");
}

static void set_macsec_es(struct pgen_token *tokens, uint32_t n_tokens)
{
    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_es_help();
        return;
    }

    if (!strcmp(tokens[1].name, "on")) {
        pgen.macsec_hdr.tci_an.es = 1;
    } else if (!strcmp(tokens[1].name, "off")) {
        pgen.macsec_hdr.tci_an.es = 0;
    } else {
        NETOS_PRINT_STD_ERROR_COLOR("invalid ES mode value <%s>\n",
                                    tokens[1].name);
    }
}

static inline void set_macsec_sc_help()
{
    NETOS_PRINT_STD_GREEN_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_GREEN_COLOR("macsec.sc <on/off> - turn MACsec SCI on or off\n");
}

static void set_macsec_sc(struct pgen_token *tokens, uint32_t n_tokens)
{
    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_sc_help();
        return;
    }

    if (!strcmp(tokens[1].name, "on")) {
        pgen.macsec_hdr.tci_an.sc = 1;
    } else if (!strcmp(tokens[1].name, "off")) {
        pgen.macsec_hdr.tci_an.sc = 0;
    } else {
        NETOS_PRINT_STD_ERROR_COLOR("invalid SC mode value <%s>\n",
                                    tokens[1].name);
    }
}

static inline void set_macsec_pn_help()
{
    fprintf(stderr, "\nHelp:\n");
    fprintf(stderr, "macsec.pn <value> - Set MACsec PN value\n");
}

static void set_macsec_pn(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_pn_help();
        return;
    }

    ret = netos_get_u32_from_str(tokens[1].name, &pgen.macsec_hdr.pn);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }
}

static inline void set_macsec_version_help()
{
    fprintf(stderr, "\nHelp:\n");
    fprintf(stderr, "macsec.version <value> - Set Version <1 bit value 0 or 1>\n");
}

static void set_macsec_version(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t val;

    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_version_help();
        return;
    }

    ret = netos_get_u32_from_str(tokens[1].name, &val);
    if (ret != NETOS_STATUS_SUCCESS) {
        return;
    }

    pgen.macsec_hdr.tci_an.v = 1;
}

static inline void set_macsec_sci_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR(
                    "macsec.sci <8 bytes> - Set the SCI value\n"
                    "macsec.sci 00:11:22:33:44:55:66:11\n");
}

static void set_macsec_sci(struct pgen_token *tokens, uint32_t n_tokens)
{
    uint32_t sci[NETOS_MACSEC_SCI_LEN] = {0};
    int ret;

    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_sci_help();
        return;
    }

    ret = sscanf(tokens[1].name,
                 "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                 &sci[0], &sci[1], &sci[2], &sci[3],
                 &sci[4], &sci[5], &sci[6], &sci[7]);
    if (ret != 8) {
        fprintf(stderr, "invalid SCI format\n");
        set_macsec_sci_help();
        return;
    }

    pgen.macsec_hdr.sci[0] = sci[0];
    pgen.macsec_hdr.sci[1] = sci[1];
    pgen.macsec_hdr.sci[2] = sci[2];
    pgen.macsec_hdr.sci[3] = sci[3];
    pgen.macsec_hdr.sci[4] = sci[4];
    pgen.macsec_hdr.sci[5] = sci[5];
    pgen.macsec_hdr.sci[6] = sci[6];
    pgen.macsec_hdr.sci[7] = sci[7];
}

static inline void set_macsec_an_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR("macsec.an <0/1/2/3>\n");
}

static void set_macsec_an(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t val;

    if ((n_tokens == 1) ||
        (!strcmp(tokens[1].name, "help")) ||
        (!strcmp(tokens[1].name, "?"))) {
        set_macsec_an_help();
        return;
    }

    ret = netos_get_u32_from_str(tokens[1].name, &val);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("Invalid MACsec an value <%s>\n", tokens[1].name);
        return;
    }

    if (val > NETOS_MACSEC_AN_LEN) {
        NETOS_PRINT_STD_ERROR_COLOR("Invalid AN value %d\n", val);
        set_macsec_an_help();
        return;
    }

    pgen.macsec_hdr.tci_an.an = val;
}

static void set_icmp_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen.icmp_enable                    = true;
    set_enable_run("icmp");
}

static inline void set_icmp_type_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR("icmp.type <0-255>\n");
}

static void set_icmp_type(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t type;

    ret = netos_get_u32_from_str(tokens[1].name, &type);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid ICMP type <%s>\n", tokens[1].name);
        set_icmp_type_help();
        return;
    }

    if (type > 255) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid ICMP type %d\n", type);
        set_icmp_type_help();
        return;
    }

    pgen.icmp_hdr.type = type;
}

static inline void set_icmp_code_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR("icmp.code <0-255>\n");
}

static void set_icmp_code(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t code;

    ret = netos_get_u32_from_str(tokens[1].name, &code);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid ICMP code <%s>\n", tokens[1].name);
        set_icmp_code_help();
        return;
    }

    if (code > 255) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid ICMP code %d\n", code);
        set_icmp_code_help();
        return;
    }

    pgen.icmp_hdr.code = code;
}

static void set_icmp_checksum(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_hex_from_str(tokens[1].name, &pgen.icmp_hdr.checksum);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid ICMP checksum value <%s>\n", tokens[1].name);
        return;
    }
}

static void set_icmp_id(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_hex_from_str(tokens[1].name, &pgen.icmp_hdr.u.echo_req.identifier);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ICMP identifier value <%s>\n", tokens[1].name);
        return;
    }
}

static void set_icmp_seq(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_from_str(tokens[1].name, &pgen.icmp_hdr.u.echo_req.seq_no);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ICMP seq_no value <%s>\n", tokens[1].name);
        return;
    }
}

static void set_ipv4_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    pgen.ipv4_enable                    = true;
    set_enable_run("ipv4");
}

static void set_ipv4_version(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t version;

    ret = netos_get_u32_from_str(tokens[1].name, &version);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ipv4 version value <%s>\n", tokens[1].name);
        return;
    }

    pgen.ipv4_hdr.version = version;
}

static void set_ipv4_src_ip(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_ipv4addr_from_str(tokens[1].name, &pgen.ipv4_hdr.src_ipaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ipv4.src_ip value <%s>\n", tokens[1].name);
        return;
    }

    pgen.ipv4_hdr.src_ipaddr = ntohl(pgen.ipv4_hdr.src_ipaddr);
}

static void set_ipv4_dst_ip(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_ipv4addr_from_str(tokens[1].name, &pgen.ipv4_hdr.dst_ipaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ipv4.dst_ip value <%s>\n", tokens[1].name);
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
        fprintf(stderr, "invalid ipv4.ttl value <%s>\n", tokens[1].name);
        return;
    }

    if (ttl > NETOS_TTL_MAX) {
        fprintf(stderr, "invalid ipv4.ttl value <%s>\n", tokens[1].name);
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
        fprintf(stderr, "invalid ipv4.protocol value <%s>\n", tokens[1].name);
        return;
    }

    pgen.ipv4_hdr.protocol = protocol;
}

static void set_ipv4_more_fragments(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    bool val;

    ret = netos_get_bool_from_str(tokens[1].name, &val);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ipv4.more_fragments value <%s>\n", tokens[1].name);
        return;
    }

    pgen.ipv4_hdr.flags.more_fragment = val;
}

static void set_ipv4_dont_fragment(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    bool val;

    ret = netos_get_bool_from_str(tokens[1].name, &val);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ipv4.dont_fragment value <%s>\n", tokens[1].name);
        return;
    }

    pgen.ipv4_hdr.flags.dont_fragment = val;
}

static void set_ipv4_chksum(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_hex_from_str(tokens[1].name, &pgen.ipv4_hdr.hdr_chksum);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid ipv4.checksum value <%s>\n", tokens[1].name);
        return;
    }
}

static void set_vlan_id(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t vid;

    ret = netos_get_u32_from_str(tokens[1].name, &vid);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invlaid vlan.id value <%s>\n", tokens[1].name);
        return;
    }

    pgen.vlan_enable        = true;
    pgen.eth_hdr.ethertype  = NETOS_ETHERTYPE_VLAN;
    pgen.vlan_hdr.vlan_id   = vid;
}

static void set_vlan_priority(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t priority;

    ret = netos_get_u32_from_str(tokens[1].name, &priority);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid vlan.priority value <%s>\n", tokens[1].name);
        return;
    }

    pgen.vlan_enable        = true;
    pgen.eth_hdr.ethertype  = NETOS_ETHERTYPE_VLAN;
    pgen.vlan_hdr.pcp       = priority;
}

static void set_vlan_next_ethertype(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_hex_from_str(tokens[1].name, &pgen.vlan_hdr.ethertype);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid vlan.next_ethertype value <%s>\n", tokens[1].name);
        return;
    }

    pgen.vlan_enable        = true;
    pgen.eth_hdr.ethertype  = NETOS_ETHERTYPE_VLAN;
}

static void set_eth_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    set_enable_run("eth");
}

static void set_arp_enable(struct pgen_token *tokens, uint32_t n_tokens)
{
    set_enable_run("arp");
}

static inline void set_arp_sha_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR(
                    "arp.sha <mac-address> - sets the sender hw addess\n"
                    "Example: arp.sha 01:01:02:03:04:05\n");
}

static void set_arp_sha(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    if ((n_tokens == 1) ||
        !strcmp(tokens[1].name, "help") ||
        !strcmp(tokens[1].name, "?")) {
        set_arp_sha_help();
        return;
    }

    ret = netos_get_mac_addr_from_str(tokens[1].name,
                                      pgen.arp_hdr.sender_hwaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid arp.sha value <%s>\n", tokens[1].name);
        set_arp_sha_help();
        return;
    }
}

static inline void set_arp_spa_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR(
                    "arp.spa <ipv4-address> - sets the sender protocol address\n"
                    "Example: arp.spa 192.168.0.1\n");
}

static void set_arp_spa(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    if ((n_tokens == 1) ||
        !strcmp(tokens[1].name, "help") ||
        !strcmp(tokens[1].name, "?")) {
        set_arp_spa_help();
        return;
    }

    ret = netos_get_ipv4addr_from_str(tokens[1].name,
                                      &pgen.arp_hdr.sender_protocol_addr);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid arp.spa value <%s>\n", tokens[1].name);
        set_arp_spa_help();
        return;
    }

    pgen.arp_hdr.sender_protocol_addr = ntohl(pgen.arp_hdr.sender_protocol_addr);
}

static void set_arp_tha_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR(
                    "arp.tha <mac-address in xx:xx:xx:xx:xx:xx> format\n"
                    "sets the ARP target hardware address\n"
                    "Example: arp.tha 00:11:00:00:00:22\n");
}

static void set_arp_tha(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    if ((n_tokens == 1) ||
        !strcmp(tokens[1].name, "help") ||
        !strcmp(tokens[1].name, "?")) {
        set_arp_tha_help();
        return;
    }

    ret = netos_get_mac_addr_from_str(tokens[1].name,
                                      pgen.arp_hdr.target_hwaddr);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid arp.tha value <%s>\n", tokens[1].name);
        return;
    }
}

static inline void set_arp_tpa_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR(
                    "arp.tpa <ipv4-address> - sets the sender protocol address\n"
                    "Example: arp.tpa 192.168.0.1\n");
}

static void set_arp_tpa(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    if ((n_tokens == 1) ||
        !strcmp(tokens[1].name, "help") ||
        !strcmp(tokens[1].name, "?")) {
        set_arp_tpa_help();
        return;
    }

    ret = netos_get_ipv4addr_from_str(tokens[1].name,
                                      &pgen.arp_hdr.target_protocol_addr);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid arp.tpa value <%s>\n", tokens[1].name);
        set_arp_tpa_help();
        return;
    }

    pgen.arp_hdr.target_protocol_addr = ntohl(pgen.arp_hdr.target_protocol_addr);
}

static inline void set_arp_op_help()
{
    NETOS_PRINT_STD_MAGENTA_COLOR("\nHelp:\n");
    NETOS_PRINT_STD_MAGENTA_COLOR("arp.op <op-val> 1 - Request, 2 - Reply\n");
}

static void set_arp_op(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;
    uint32_t op;

    if ((n_tokens == 1) ||
        !strcmp(tokens[1].name, "help") ||
        !strcmp(tokens[1].name, "?")) {
        set_arp_op_help();
        return;
    }

    ret = netos_get_u32_from_str(tokens[1].name, &op);
    if (ret != NETOS_STATUS_SUCCESS) {
        fprintf(stderr, "invalid arp.op value <%s>\n", tokens[1].name);
        return;
    }
    if ((op < 1) || (op > 2)) {
        fprintf(stderr, "invalid arp.op value <%s>\n", tokens[1].name);
        set_arp_op_help();
        return;
    }

    pgen.arp_hdr.op = op;
}

static void set_eth_da(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_mac_addr_from_str(tokens[1].name, pgen.eth_hdr.dst);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid eth.da value <%s>\n", tokens[1].name);
        return;
    }
}

static void set_eth_sa(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_mac_addr_from_str(tokens[1].name, pgen.eth_hdr.src);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid eth.sa <%s>\n", tokens[1].name);
        return;
    }
}

static void set_eth_ethertype(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u16_hex_from_str(tokens[1].name, &pgen.eth_hdr.ethertype);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid eth.ethertype <%s>\n", tokens[1].name);
        return;
    }
}

static void set_ipg(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u64_from_str(tokens[1].name, &pgen.ipg_ns);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid ipg value <%s>\n", tokens[1].name);
        return;
    }
}

static void set_n_frames(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u32_from_str(tokens[1].name, &pgen.n_frames);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid n_frames value <%s>\n", tokens[1].name);
        return;
    }
}

static void set_packet_len(struct pgen_token *tokens, uint32_t n_tokens)
{
    netos_status_t ret;

    ret = netos_get_u32_from_str(tokens[1].name, &pgen.len);
    if (ret != NETOS_STATUS_SUCCESS) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid pkt len <%s>\n", tokens[1].name);
        return;
    }
}

static void set_ifname(struct pgen_token *tokens, uint32_t n_tokens)
{
    if (pgen.ifname) {
        free(pgen.ifname);
    }

    pgen.ifname = strdup(tokens[1].name);
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
    if (pgen.vlan_enable) {
        pgen.vlan_hdr.ethertype = NETOS_ETHERTYPE_ARP;
    } else {
        pgen.eth_hdr.ethertype = NETOS_ETHERTYPE_ARP;
    }
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
    } else {
        pgen.ipv4_hdr.gen_checksum = false;
    }
    netos_ipv4_encode(&pgen.ipv4_hdr, &pkt_buf);

    if ((pgen.len != 0) && (pgen.len < sizeof(data_buf) - 80)) {
        pkt_buffer_encode_bytes(&pkt_buf, data_buf, pgen.len);
    }

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_ipv6_run()
{
    uint8_t data_buf[1024] = {0};
    pkt_buffer_t pkt_buf;

    pkt_buffer_initialize(&pkt_buf);
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);

    netos_ipv6_encode(&pgen.ipv6_hdr, &pkt_buf);

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

    if (pgen.vlan_enable) {
        pgen.eth_hdr.ethertype = NETOS_ETHERTYPE_VLAN;
    }
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);
    if (pgen.vlan_enable) {
        netos_vlan_encode(&pgen.vlan_hdr, &pkt_buf);
    }
    pgen.ipv4_hdr.gen_checksum = true;
    pgen.ipv4_hdr.protocol = NETOS_PROTOCOL_ICMP;
    pgen.ipv4_hdr.total_len = NETOS_ICMP_HDR_LEN + pgen.len;
    netos_ipv4_encode(&pgen.ipv4_hdr, &pkt_buf);

    if (pgen.len == 0) {
        pgen.icmp_hdr.u.echo_req.data = NULL;
        pgen.icmp_hdr.u.echo_req.data_len = 0;
    } else {
        pgen.icmp_hdr.u.echo_req.data = data_buf;
        pgen.icmp_hdr.u.echo_req.data_len = pgen.len;
    }

    if (pgen.icmp_hdr.checksum == 0) {
        pgen.icmp_hdr.gen_checksum = true;
    } else {
        pgen.icmp_hdr.gen_checksum = false;
    }
    netos_icmp_encode(&pgen.icmp_hdr, &pkt_buf);

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_macsec_run()
{
    uint8_t data_buf[1024] = {0};
    pkt_buffer_t pkt_buf;
    netos_status_t ret;
    uint8_t iv[12] = {0};
    uint8_t tag[16] = {0};

    pkt_buffer_initialize(&pkt_buf);
    pgen.eth_hdr.ethertype = NETOS_ETHERTYPE_MACSEC;
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);

    pgen.macsec_hdr.hdr_len = 0;
    pgen.macsec_hdr.sl = 0;
    pgen.macsec_hdr.data = data_buf;
    if (pgen.len < 48) {
        pgen.macsec_hdr.sl = pgen.len;
    }

    netos_macsec_encode(&pgen.macsec_hdr, &pkt_buf);

    if ((pgen.macsec_hdr.tci_an.e == 0) &&
        (pgen.macsec_hdr.tci_an.c == 1)) {
        uint16_t aad_off_start = pkt_buf.offset;
        memcpy(data_buf, &pkt_buf.buffer[aad_off_start], pgen.macsec_hdr.hdr_len);
        netos_crypto_aes_gmac_params_t gmac_params = {
            .aad        = data_buf,
            .aad_len    = pgen.macsec_hdr.hdr_len + pgen.len,
            .iv         = iv,
            .tag        = tag,
        };
        ret = netos_crypto_generate_gmac(pgen.crypto_ctx,
                                         pgen.gcm_ctx,
                                         &gmac_params);
        if (ret != NETOS_STATUS_SUCCESS) {
            printf("failed to perform crypto GMAC\n");
            return;
        }
        pkt_buffer_encode_bytes(&pkt_buf, &data_buf[pgen.macsec_hdr.hdr_len], pgen.len);
    } else if (pgen.macsec_hdr.tci_an.e &&
               pgen.macsec_hdr.tci_an.c) {
        uint32_t aad_len = pgen.macsec_hdr.hdr_len - 2 + NETOS_ETH_HDR_LEN;
        uint8_t *in_data_ptr = data_buf;
        uint8_t *out_data_ptr = &pkt_buf.buffer[aad_len];
        netos_crypto_aes_gcm_params_t gcm_params = {
            .aad            = &pkt_buf.buffer[0],
            .aad_len        = aad_len,
            .in_msg         = in_data_ptr,
            .in_msg_len     = pgen.len,
            .out_msg        = out_data_ptr,
            .out_msg_len    = pgen.len,
            .iv             = iv,
            .tag            = tag,
        };
        ret = netos_crypto_encrypt_gcm(pgen.crypto_ctx,
                                       pgen.gcm_ctx,
                                       &gcm_params);
        if (ret != NETOS_STATUS_SUCCESS) {
            printf("failed to perform encrypt GCM\n");
            return;
        }
        pkt_buf.offset += pgen.len;
    }

    pkt_buffer_encode_bytes(&pkt_buf, tag, 16);

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}

static void pgen_pcap_run()
{
    pkt_buffer_t pkt_buf;
    netos_pcap_packet_header_t *pkt_hdr = NULL;
    uint32_t n_replayed = 0;
    netos_status_t ret;

    do {
        pkt_buffer_initialize(&pkt_buf);
        uint8_t *buffer = NULL;

        ret = netos_pcap_read_file_entry(pgen.pcap_ctx, &pkt_hdr, &buffer);
        if (ret != NETOS_STATUS_SUCCESS) {
            if (ret == NETOS_STATUS_PCAP_EOF) {
                fprintf(stderr, "end of pcap record\n");
            } else {
                fprintf(stderr, "invalid pcap record\n");
            }
            break;
        }

        memcpy(pkt_buf.buffer, buffer, pkt_hdr->incl_len);
        pkt_buf.offset = pkt_hdr->incl_len;
        pkt_buffer_set_tx_len_default(&pkt_buf);
        netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);

        n_replayed ++;

        struct timespec tp = {
            .tv_sec  = 0,
            .tv_nsec = pgen.ipg_ns,
        };

        clock_nanosleep(CLOCK_REALTIME, 0, &tp, NULL);
    } while (1);

    fprintf(stderr, "Replay complete, sent %d frames over [%s]\n", n_replayed, pgen.ifname);
}

#if 0
static void pgen_udp_run()
{
    uint8_t data_buf[1024] = {0};
    pkt_buffer_t pkt_buf;

    pkt_buffer_initialize(&pkt_buf);
    netos_eth_encode(&pgen.eth_hdr, &pkt_buf);

    if (pgen.ipv4_hdr.hdr_chksum == 0) {
        pgen.ipv4_hdr.gen_checksum = true;
    } else {
        pgen.ipv4_hdr.gen_checksum = false;
    }
    netos_ipv4_encode(&pgen.ipv4_hdr, &pkt_buf);

    if ((pgen.len != 0) && (pgen.len < sizeof(data_buf) - 80)) {
        pkt_buffer_encode_bytes(&pkt_buf, data_buf, pgen.len);
    }

    netos_udp_encode(&pgen.udp_hdr, &pkt_buf);

    pkt_buffer_set_tx_len_default(&pkt_buf);
    netos_raw_socket_tx(pgen.raw, pkt_buf.buffer, pkt_buf.tx_len);
}
#endif

static void pgen_run(struct pgen_token *tokens, uint32_t n_tokens)
{
    if (!pgen.ifname) {
        fprintf(stderr, "Interface name is not present. "
                        "Interface should be provided via ifname\n");
        return;
    }

    pgen.raw = netos_raw_socket_init(pgen.ifname);
    if (!pgen.raw) {
        fprintf(stderr, "Failed to create a raw socket.. "
                        "is the interface available and up?\n");
        return;
    }

    uint32_t i;

    void (*callback_ptr)() = NULL;

    for (i = 0; i < NETOS_SIZEOF_ARRAY(pgen_run_callback_list); i ++) {
        if (pgen_run_callback_list[i].enable) {
            callback_ptr = pgen_run_callback_list[i].callback;
            break;
        }
    }

    if (!callback_ptr) {
        fprintf(stderr, "No protocol generation enabled!\n");
        return;
    }

    struct pgen_run_callback *pgen_cb = get_run_cb("pgen");
    // pcap config is enabled
    if (pgen_cb && pgen_cb->enable) {
        pgen_cb->callback();
    } else {
        for (i = 0; i < pgen.n_frames; i ++) {

            callback_ptr();

            struct timespec tp = {
                .tv_sec  = 0,
                .tv_nsec = pgen.ipg_ns,
            };

            clock_nanosleep(CLOCK_REALTIME, 0, &tp, NULL);
        }
        fprintf(stderr, "sent %d frames\n", pgen.n_frames);
    }
}

static void pgen_listen(struct pgen_token *tokens, uint32_t n_tokens)
{
    if (!pgen.ifname) {
        fprintf(stderr, "Interface name is not present. "
                        "Interface should be provided via ifname\n");
        return;
    }

    pgen.raw = netos_raw_socket_init(pgen.ifname);
    if (!pgen.raw) {
        fprintf(stderr, "Failed to create a raw socket.. "
                        "is the interface available and up?\n");
        return;
    }

    uint32_t i;

    void (*callback_ptr)(netos_raw_socket_ctx_t *, void *) = NULL;
    void *(*fill_callback)() = NULL;
    void (*free_callback)(void *) = NULL;

    for (i = 0; i < NETOS_SIZEOF_ARRAY(pgen_run_callback_list); i ++) {
        if (pgen_run_callback_list[i].enable) {
            callback_ptr = pgen_run_callback_list[i].listen_callback;
            fill_callback = pgen_run_callback_list[i].fill_callback;
            free_callback = pgen_run_callback_list[i].free_callback;
            break;
        }
    }

    if (!callback_ptr || !fill_callback || !free_callback) {
        fprintf(stderr, "No protocol listen enabled!\n");
        return;
    }

    void *config = fill_callback();
    if (config) {
        callback_ptr(pgen.raw, config);
        free_callback(config);
    }
}

static void *pgen_arp_fill()
{
    netos_pgen_arp_config_t *arp_config;

    arp_config = calloc(1, sizeof(netos_pgen_arp_config_t));
    if (!arp_config) {
        return NULL;
    }

    return arp_config;
}

static void pgen_arp_free(void *config)
{
    free(config);
}

static void pgen_exit(struct pgen_token *tokens, uint32_t n_tokens)
{
    fprintf(stderr, "exiting the pgen..\n");
    exit(1);
}

/**
 * Defines a list of pgen callbacks for function implementations.
 */
struct pgen_sub_command {
    const char *cmd_name;
    const char *cmd_desc;
    void        (*callback)(struct pgen_token *tokens, uint32_t n_tokens);
};

static const struct pgen_sub_command pgen_sub_command_common[] = {
    { IPG_CMD,              IPG_STR,                set_ipg },
    { N_FRAMES_CMD,         N_FRAMES_STR,           set_n_frames },
    { LEN_CMD,              LEN_STR,                set_packet_len },
    { IFNAME_CMD,           IFNAME_STR,             set_ifname },
    { RUN_CMD,              RUN_STR,                pgen_run },
    { LISTEN_CMD,           LISTEN_STR,             pgen_listen },
    { EXIT_CMD,             EXIT_STR,               pgen_exit },
    { QUIT_CMD,             QUIT_STR,               pgen_exit },
    { HELP_CMD,             HELP_STR,               pgen_help },
};

static const struct pgen_sub_command pgen_sub_command_pcap[] = {
    { PCAP_ENABLE_CMD,      PCAP_ENABLE_STR,        set_pcap_enable },
    { PCAP_OPEN_CMD,        PCAP_OPEN_STR,          set_pcap_open },
};

static const struct pgen_sub_command pgen_sub_command_eth[] = {
    { ETH_ENABLE_CMD,       ETH_ENABLE_STR,         set_eth_enable },
    { ETH_DA_CMD,           ETH_DA_STR,             set_eth_da },
    { ETH_SA_CMD,           ETH_SA_STR,             set_eth_sa },
    { ETH_ETHERTYPE_CMD,    ETH_ETHERTYPE_STR,      set_eth_ethertype },
};

static const struct pgen_sub_command pgen_sub_command_arp[] = {
    { ARP_ENABLE_CMD,       ARP_ENABLE_STR,         set_arp_enable },
    { ARP_OP_CMD,           ARP_OP_STR,             set_arp_op },
    { ARP_SHA_CMD,          ARP_SHA_STR,            set_arp_sha },
    { ARP_SPA_CMD,          ARP_SPA_STR,            set_arp_spa },
    { ARP_THA_CMD,          ARP_THA_STR,            set_arp_tha },
    { ARP_TPA_CMD,          ARP_TPA_STR,            set_arp_tpa },
};

static const struct pgen_sub_command pgen_sub_command_vlan[] = {
    { VLAN_ID_CMD,          VLAN_ID_STR,            set_vlan_id },
    { VLAN_PRIORITY_CMD,    VLAN_PRIORITY_STR,      set_vlan_priority },
    { VLAN_NEXT_ETHER_CMD,  VLAN_NEXT_ETHER_STR,    set_vlan_next_ethertype },
};

static const struct pgen_sub_command pgen_sub_command_ipv4[] = {
    { IPV4_ENABLE_CMD,      IPV4_ENABLE_STR,        set_ipv4_enable },
    { IPV4_VERSION_CMD,     IPV4_VERSION_STR,       set_ipv4_version },
    { IPV4_SRC_IP_CMD,      IPV4_SRC_IP_STR,        set_ipv4_src_ip },
    { IPV4_DST_IP_CMD,      IPV4_DST_IP_STR,        set_ipv4_dst_ip },
    { IPV4_TTL_CMD,         IPV4_TTL_STR,           set_ipv4_ttl },
    { IPV4_PROTOCOL_CMD,    IPV4_PROTOCOL_STR,      set_ipv4_protocol },
    { IPV4_MF_CMD,          IPV4_MF_STR,            set_ipv4_more_fragments },
    { IPV4_DF_CMD,          IPV4_DF_STR,            set_ipv4_dont_fragment },
    { IPV4_CHKSUM_CMD,      IPV4_CHKSUM_STR,        set_ipv4_chksum },
};

static const struct pgen_sub_command pgen_sub_command_icmp[] = {
    { ICMP_ENABLE_CMD,      ICMP_ENABLE_STR,        set_icmp_enable },
    { ICMP_TYPE_CMD,        ICMP_TYPE_STR,          set_icmp_type },
    { ICMP_CODE_CMD,        ICMP_CODE_STR,          set_icmp_code },
    { ICMP_CHECKSUM_CMD,    ICMP_CHECKSUM_STR,      set_icmp_checksum },
    { ICMP_ID_CMD,          ICMP_ID_STR,            set_icmp_id },
    { ICMP_SEQ_CMD,         ICMP_SEQ_STR,           set_icmp_seq },
};

static const struct pgen_sub_command pgen_sub_command_macsec[] = {
    { MACSEC_ENABLE_CMD,    MACSEC_ENABLE_STR,      set_macsec_enable },
    { MACSEC_KEY_CMD,       MACSEC_KEY_STR,         set_macsec_key },
    { MACSEC_ENCRYPT_CMD,   MACSEC_ENCRYPT_STR,     set_macsec_encrypt },
    { MACSEC_CHANGED_CMD,   MACSEC_CHANGED_STR,     set_macsec_changed },
    { MACSEC_ES_CMD,        MACSEC_ES_STR,          set_macsec_es },
    { MACSEC_SC_CMD,        MACSEC_SC_STR,          set_macsec_sc },
    { MACSEC_PN_CMD,        MACSEC_PN_STR,          set_macsec_pn },
    { MACSEC_V_CMD,         MACSEC_V_STR,           set_macsec_version },
    { MACSEC_AN_CMD,        MACSEC_AN_STR,          set_macsec_an },
    { MACSEC_SCI_CMD,       MACSEC_SCI_STR,         set_macsec_sci },
};

static const struct {
    const char *name;
    const char *desc;
    const struct pgen_sub_command *sub_cmd;
    uint32_t sub_cmd_len;
} pgen_command_list[] = {
    { ETH_CMD,    ETH_CMD_DESC,    pgen_sub_command_eth,    NETOS_SIZEOF_ARRAY(pgen_sub_command_eth) },
    { MACSEC_CMD, MACSEC_CMD_DESC, pgen_sub_command_macsec, NETOS_SIZEOF_ARRAY(pgen_sub_command_macsec) },
    { ARP_CMD,    ARP_CMD_DESC,    pgen_sub_command_arp,    NETOS_SIZEOF_ARRAY(pgen_sub_command_arp) },
    { VLAN_CMD,   VLAN_CMD_DESC,   pgen_sub_command_vlan,   NETOS_SIZEOF_ARRAY(pgen_sub_command_vlan) },
    { IPV4_CMD,   IPV4_CMD_DESC,   pgen_sub_command_ipv4,   NETOS_SIZEOF_ARRAY(pgen_sub_command_ipv4) },
    { ICMP_CMD,   ICMP_CMD_DESC,   pgen_sub_command_icmp,   NETOS_SIZEOF_ARRAY(pgen_sub_command_icmp) },
    { PCAP_CMD,   PCAP_CMD_DESC,   pgen_sub_command_pcap,   NETOS_SIZEOF_ARRAY(pgen_sub_command_pcap) },
    { COMMON_CMD, COMMON_CMD_DESC, pgen_sub_command_common, NETOS_SIZEOF_ARRAY(pgen_sub_command_common) },
};

static void pgen_help(struct pgen_token *tokens, uint32_t n_tokens)
{
    uint32_t i;

    NETOS_PRINT_STD_GREEN_COLOR("----------------------------------------------------------\n");
    for (i = 0; i < NETOS_SIZEOF_ARRAY(pgen_command_list); i ++) {
        NETOS_PRINT_STD_GREEN_COLOR("%-30s %s\n",
                                    pgen_command_list[i].name,
                                    pgen_command_list[i].desc);
    }
    NETOS_PRINT_STD_GREEN_COLOR("----------------------------------------------------------\n");
}

static void pgen_sub_command_help(uint32_t cmd_idx)
{
    uint32_t i;

    for (i = 0; i < pgen_command_list[cmd_idx].sub_cmd_len; i ++) {
        const struct pgen_sub_command *sub_cmd = pgen_command_list[cmd_idx].sub_cmd;

        NETOS_PRINT_STD_GREEN_COLOR("%-30s %s\n", sub_cmd[i].cmd_name, sub_cmd[i].cmd_desc);
    }
}

/**
 * @brief - tokenize the input string split with ' '
 *
 * @param [in] buf - input buffer.
 * @param [in] len - input buffer length.
 * @param [inout] tokens - list of split tokens.
 *
 * @return returns number of tokens parsed in the buffer.
 */
static uint32_t pgen_tokenize(const char *buf, uint32_t len, struct pgen_token *tokens)
{
    char tmp[128];
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
            if (j >= sizeof(tmp)) {
                NETOS_PRINT_STD_ERROR_COLOR("Token size exceeds buffer size %ld failed parsing the token\n",
                                            sizeof(tmp));
                return 0; // no tokens to run
            }
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

/**
 * @brief - Scan all the callbacks and find the matching callback for the input command and execute it.
 *
 * @param [in] cmd_idx - command id.
 * @param [in] tokens - list of input tokens.
 * @param [in] n_tokens - number of tokens.
 *
 * @return returns true if command is found and the callback is run, false if not.
 */
static bool pgen_process_sub_commands(uint32_t cmd_idx, struct pgen_token *tokens, uint32_t n_tokens)
{
    uint32_t j;

    const struct pgen_sub_command *sub_cmd = pgen_command_list[cmd_idx].sub_cmd;

    for (j = 0; j < pgen_command_list[cmd_idx].sub_cmd_len; j ++) {
        if (!strcmp(sub_cmd[j].cmd_name, tokens[0].name)) {
            sub_cmd[j].callback(tokens, n_tokens);
            return true;
        }
    }

    return false;
}

int main(int argc, char **argv)
{
    pgen_set_defaults();

    while (1) {
        char *buf = readline("pgen> ");

        if (!buf) {
            break;
        }

        uint32_t len = strlen(buf);
        buf[len] = '\0';

        if (len < 1) {
            free(buf);
            continue;
        }

        add_history(buf);

        struct pgen_token tokens[10];
        uint32_t n_tokens;

        memset(tokens, 0, sizeof(tokens));
        n_tokens = pgen_tokenize(buf, len, tokens);
        if (n_tokens != 0) {
            uint32_t i;
            bool valid_cmd = false;
            bool display_help = false;

            // user has pressed help
            if (!strcmp(tokens[0].name, "help")) {
                pgen_help(tokens, n_tokens);
                free(buf);
                continue;
            }

            // if any commands are matching just the name then display this
            for (i = 0; i < NETOS_SIZEOF_ARRAY(pgen_command_list); i ++) {
                if (!strcmp(pgen_command_list[i].name, tokens[0].name)) {
                    pgen_sub_command_help(i);
                    display_help = true;
                    break;
                }
            }

            // scan for possible commands and run the setter / run callback
            for (i = 0; (i < NETOS_SIZEOF_ARRAY(pgen_command_list) && !display_help); i ++) {
                valid_cmd = pgen_process_sub_commands(i, tokens, n_tokens);
                if (valid_cmd) {
                    break;
                }
            }

            if (!valid_cmd && !display_help) {
                fprintf(stderr, "Invalid command <%s>\n", buf);
            }
        } else {
            NETOS_PRINT_STD_ERROR_COLOR("Incorrect token sequence\n");
        }
        free(buf);
    }
    return 0;
}

