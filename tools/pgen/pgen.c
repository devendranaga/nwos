#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pgen.h"

static struct pgen pgen;

struct pgen_token {
    char *name;
};

static void pgen_set_defaults()
{
    uint8_t dst[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    uint8_t src[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x01};
    uint16_t ethertype = 0x0800;

    memcpy(pgen.eth_hdr.dst, dst, NETOS_MACADDR_LEN);
    memcpy(pgen.eth_hdr.src, src, NETOS_MACADDR_LEN);
    pgen.eth_hdr.ethertype = ethertype;
}

void set_eth_da(struct pgen_token *tokens, uint32_t n_tokens)
{

}

struct netos_pgen_callbacks {
    const char *str;
    void (*callback)(struct pgen_token *tokens, uint32_t n_tokens);
} pgen_setup_callbacks[] = {
    {"eth.da", set_eth_da}
};

static uint32_t pgen_tokenize(char *buf, uint32_t len, struct pgen_token *tokens)
{
    return 0;
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

            for (i = 0; i < sizeof(pgen_setup_callbacks) / sizeof(pgen_setup_callbacks[0]); i ++) {
            }
        }
    }
    return 0;
}

