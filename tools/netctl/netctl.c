#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "intf_statistics.h"
#include "netctl_intf.h"
#include "netctl.h"
#include "netos_status.h"
#include "netos_log.h"
#include "unix_intf.h"
#include "common.h"

struct netctl_tokens {
    char token[32];
};

static struct netctl_tokens tokens[20];

static int netos_netctl_parse_input(char *input_stream, uint32_t input_stream_len)
{
    char tmp[128];
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t token_idx = 0;

    while (input_stream[i] != '\0') {
        if (input_stream[i] == ' ') {
            tmp[j] = '\0';
            strcpy(tokens[token_idx].token, tmp);
            token_idx ++;
            j = 0;
            i ++;
        } else {
            if (j >= sizeof(tmp)) {
                NETOS_PRINT_STD_ERROR_COLOR("Token size exceeds buffer size %ld failed parsing the token\n",
                                            sizeof(tmp));
                return 0;
            }
            tmp[j] = input_stream[i];
            j ++;
            i ++;
        }
    }

    tmp[j] = '\0';
    strcpy(tokens[token_idx].token, tmp);
    token_idx ++;

    return token_idx;
}

static void netos_netctl_rx_show_ingress_stats(netos_netctl_t *ctl, uint32_t command)
{
    char path[128];
    uint8_t rx_msg[2048];
    netos_netctl_intf_t *intf_msg = (netos_netctl_intf_t *)rx_msg;
    int remaining_len = 0;
    uint8_t *start_data;
    int ret;

    ret = netos_unix_intf_udp_recv(ctl->fd, path, sizeof(path), rx_msg, sizeof(rx_msg));
    if (ret < 0) {
        NETOS_PRINT_STD_ERROR_COLOR("failed to read response fom the netosd\n");
        return;
    }

    // validate short length
    if ((uint32_t)ret <= sizeof(netos_netctl_intf_t)) {
        NETOS_PRINT_STD_ERROR_COLOR("no valid response from the netosd\n");
        return;
    }

    ret -= sizeof(netos_netctl_intf_t);

    if (intf_msg->version != NETOS_NETCTL_VERSION) {
        NETOS_PRINT_STD_ERROR_COLOR("invalid interface version\n");
        return;
    }

    start_data = rx_msg + sizeof(netos_netctl_intf_t);

    netos_log_info("Ingress_Stats:\n");

    while (remaining_len < ret) {
        netos_netctl_ingress_statistics_t *ingress_stats = (netos_netctl_ingress_statistics_t *)(start_data + remaining_len);

        netos_log_info("\t interface : %s\n", ingress_stats->ifname);
        netos_log_info("\t n_rx      : %d\n", ingress_stats->n_rx);
        netos_log_info("\t n_arp_rx  : %d\n", ingress_stats->n_arp_rx);
        netos_log_info("\t n_ipv4_rx : %d\n", ingress_stats->n_ipv4_rx);
        netos_log_info("\t n_ipv6_rx : %d\n", ingress_stats->n_ipv6_rx);

        remaining_len += sizeof(netos_netctl_ingress_statistics_t);
    }
}

static struct netos_netctl_sub_commands {
    char *cmd_str;
    uint32_t cmd;
    void (*rx_callback)(netos_netctl_t *ctl, uint32_t command);
} show_sub_commands[] = {
    {"interfaces",      NETOS_NETCTL_GET_INTERFACES,    NULL},
    {"ingress_stats",   NETOS_NETCTL_GET_INGRESS_STATS, netos_netctl_rx_show_ingress_stats},
    {"egress_stats",    NETOS_NETCTL_GET_EGRESS_STATS,  NULL}
};

static void netos_netctl_send_req(netos_netctl_t *ctl, uint32_t command)
{
    uint8_t send_msg[2048];
    netos_netctl_intf_t *intf_msg = (netos_netctl_intf_t *)send_msg;

    NETOS_NETCTL_INTF_INIT(intf_msg, command);

    netos_unix_intf_udp_send(ctl->fd, ctl->serv_path, send_msg, sizeof(netos_netctl_intf_t));
}

static void netos_netctl_run_show(netos_netctl_t *ctl, struct netctl_tokens *in_tokens, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < NETOS_SIZEOF_ARRAY(show_sub_commands); i ++) {
        if (!strcmp(show_sub_commands[i].cmd_str, in_tokens[1].token)) {
            netos_netctl_send_req(ctl, show_sub_commands[i].cmd);
            if (show_sub_commands[i].rx_callback) {
                show_sub_commands[i].rx_callback(ctl, show_sub_commands[i].cmd);
            }
            break;
        }
    }
}

static struct {
    char *command;
    void (*callback)(netos_netctl_t *ctl, struct netctl_tokens *tokens, uint32_t len);
} commands[] = {
    {
        "show",
        netos_netctl_run_show
    },
};

static int netos_netctl_init(netos_netctl_t *ctl)
{
    ctl->fd = netos_unix_intf_udp_server_socket_init(ctl->path);
    if (ctl->fd < 0) {
        return -1;
    }

    return 0;
}

static void netos_netctl_run(netos_netctl_t *ctl)
{
    uint32_t token_len;
    uint32_t i;

    while (1) {
        char *buf = readline("netctl> ");

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

        token_len = netos_netctl_parse_input(buf, len);

        for (i = 0; i < NETOS_SIZEOF_ARRAY(commands); i ++) {
            if (strcmp(tokens[i].token, commands[i].command) == 0) {
                commands[i].callback(ctl, tokens, token_len);
                break;
            }
        }
    }
}

static void usage(const char *progname)
{
    netos_log_info("%s <-p unix socket path> <-s netosd socket path>\n");
}

static int netos_netctl_parse_cmdargs(netos_netctl_t *ctl,
                                      int argc,
                                      char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "p:s:")) != -1) {
        switch (ret) {
            case 'p':
                ctl->path = strdup(optarg);
            break;
            case 's':
                ctl->serv_path = strdup(optarg);
            break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    netos_netctl_t ctl;
    int ret;

    ret = netos_netctl_parse_cmdargs(&ctl, argc, argv);
    if (ret != 0) {
        return ret;
    }

    ret = netos_netctl_init(&ctl);
    if (ret != 0) {
        return ret;
    }

    netos_netctl_run(&ctl);

    return 0;
}

