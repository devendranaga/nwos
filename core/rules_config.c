#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "netos_status.h"
#include "mmap_intf.h"
#include "rules_config.h"
#include "netos_log.h"

struct netos_rule_token {
    char token[1024];
};

static struct netos_rule_token tokens[20];

static uint32_t netos_rule_tokenize(const char *buf)
{
    uint32_t count = 0;
    uint32_t j = 0;
    uint32_t i = 0;

    while (buf[i] != '\0') {
        if (buf[i] == ',') {
            tokens[count].token[j] = '\0';
            j = 0;
            count ++;
        } else {
            while ((j == 0) && (buf[i] == ' ')) {
                i ++;
            }
            tokens[count].token[j] = buf[i];
            j ++;
        }
        i ++;
    }

    tokens[count].token[j] = '\0';
    count ++;

    return count;
}

static netos_rule_config_t *netos_rule_parse(const char *buf)
{
    netos_rule_config_t *rule;
    uint32_t n_tokens;

    n_tokens = netos_rule_tokenize(buf);
    if (n_tokens == 0) {
        return NULL;
    }

    rule = calloc(1, sizeof(netos_rule_config_t));
    if (!rule) {
        return NULL;
    }

    return NULL;
}

netos_status_t netos_rule_config_parse(const char *file, netos_rules_t *rules)
{
    char buf[1024] = {0};
    FILE *fp;

    fp = fopen(file, "r");
    if (!fp) {
        return NETOS_STATUS_RULE_FILE_OPEN_FAILURE;
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        uint32_t len = strlen(buf) - 1;
        buf[len] = '\0';

        if ((buf[0] == '#') || (len <= 1)) {
            continue;
        }

        netos_rule_parse(buf);
    }

    fclose(fp);

    return NETOS_STATUS_SUCCESS;
}

