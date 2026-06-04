#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netos_status.h"
#include "egress_sp.h"
#include "egress_controller.h"

netos_egress_controller_t *netos_egress_controller_init(netos_egress_queueing_alg_t alg,
                                                        raw_socket_ctx_t *raw)
{
    netos_egress_controller_t *egress_ctrl;
    netos_status_t ret;

    egress_ctrl = calloc(1, sizeof(netos_egress_controller_t));
    if (!egress_ctrl) {
        return NULL;
    }

    if (alg == NETOS_EGRESS_ALG_SP) {
        egress_ctrl->sp = calloc(1, sizeof(netos_egress_sp_mgr_t));
        if (!egress_ctrl->sp) {
            goto err;
        }

        ret = netos_egress_sp_init(egress_ctrl->sp);
        if (ret != NETOS_STATUS_SUCCESS) {
            goto err;
        }
    }

    return egress_ctrl;

err:
    if (egress_ctrl) {
        if (egress_ctrl->sp) {
            free(egress_ctrl->sp);
        }
        free(egress_ctrl);
    }

    return NULL;
}

void netos_egress_controller_deinit(netos_egress_controller_t *egress_ctrl)
{
    if (egress_ctrl) {
        if (egress_ctrl->sp) {
            free(egress_ctrl->sp);
        }
        free(egress_ctrl);
    }
}
