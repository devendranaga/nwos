#ifndef NETOS_CTRL_INTF_H
#define NETOS_CTRL_INTF_H

typedef struct {
    int     fd;
    char    *path;
} netos_ctrl_intf_ctx_t;

void *netos_ctrl_intf_init(const char *path,
                           netos_gcd_ctx_t *gcd);

#endif

