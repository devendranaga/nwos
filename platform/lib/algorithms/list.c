#include <stdio.h>
#include <stdlib.h>

struct netos_list {
    void *data;
    struct netos_list *next;
};

struct netos_list_ctx {
    struct netos_list *head;
    struct netos_list *tail;
    struct netos_list *iter_next;
};

void *netos_list_init()
{
    struct netos_list_ctx *ctx;

    ctx = calloc(1, sizeof(struct netos_list_ctx));
    if (!ctx) {
        return NULL;
    }

    return ctx;
}

void netos_list_add(void *ptr, void *data)
{
    struct netos_list_ctx *ctx = ptr;
    struct netos_list *node;

    node = calloc(1, sizeof(struct netos_list));
    if (!node) {
        return;
    }

    node->data = data;

    if (!ctx->head) {
        ctx->head = node;
        ctx->tail = node;
    } else {
        ctx->tail->next = node;
        ctx->tail = node;
    }
}


