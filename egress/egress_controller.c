#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netos_status.h"
#include "egress_sp.h"
#include "egress_rr.h"
#include "egress_controller.h"
#include "netos_log.h"

typedef netos_status_t (*egress_queue_alg_init)(netos_egress_controller_t *egress_ctrl);
typedef void (*egress_queue_alg_run)(void *queue_ctrl_ctx, pkt_buffer_t *pkt_buf);
typedef void (*egress_queue_alg_deinit)(netos_egress_controller_t *egress_ctrl);

static netos_status_t netos_egress_alg_sp_init(netos_egress_controller_t *egress_ctrl);
static void netos_egress_alg_sp_deinit(netos_egress_controller_t *egress_ctrl);
static netos_status_t netos_egress_alg_rr_init(netos_egress_controller_t *egress_ctrl);
static void netos_egress_alg_rr_deinit(netos_egress_controller_t *egress_ctrl);

static struct {
    netos_egress_queueing_alg_t alg;
    const char                  *name;
    void                        *queue_ctrl_ctx;
    egress_queue_alg_run        queue_alg_run;
    egress_queue_alg_init       queue_alg_init;
    egress_queue_alg_deinit     queue_alg_deinit;
    uint64_t                    use_count;
} egress_alg_list[] = {
    {
        NETOS_EGRESS_ALG_SP,
        "Strict Priority",
        NULL,
        netos_egress_sp_enque,
        netos_egress_alg_sp_init,
        netos_egress_alg_sp_deinit,
        0,
    },
    {
        NETOS_EGRESS_ALG_RR,
        "Round Robin",
        NULL,
        netos_egress_rr_enque,
        netos_egress_alg_rr_init,
        netos_egress_alg_rr_deinit,
        0,
    }
};

static netos_status_t netos_egress_alg_sp_init(netos_egress_controller_t *egress_ctrl)
{
    netos_status_t ret;

    egress_ctrl->sp = calloc(1, sizeof(netos_egress_sp_mgr_t));
    if (!egress_ctrl->sp) {
        goto err;
    }

    ret = netos_egress_sp_init(egress_ctrl->sp);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    egress_alg_list[NETOS_EGRESS_ALG_SP].queue_ctrl_ctx = egress_ctrl->sp;

    return NETOS_STATUS_SUCCESS;

err:
    if (egress_ctrl->sp) {
        free(egress_ctrl->sp);
    }

    return NETOS_STATUS_EGRESS_SP_INIT_FAILED;
}

static void netos_egress_alg_sp_deinit(netos_egress_controller_t *egress_ctrl)
{
    if (egress_ctrl->sp) {
        netos_egress_sp_deinit(egress_ctrl->sp);
        free(egress_ctrl->sp);
    }
    egress_ctrl->sp = NULL;
}

static netos_status_t netos_egress_alg_rr_init(netos_egress_controller_t *egress_ctrl)
{
    netos_status_t ret;

    egress_ctrl->rr = calloc(1, sizeof(netos_egress_rr_mgr_t));
    if (!egress_ctrl->rr) {
        goto err;
    }

    ret = netos_egress_rr_init(egress_ctrl->rr);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    egress_alg_list[NETOS_EGRESS_ALG_RR].queue_ctrl_ctx = egress_ctrl->rr;

    return NETOS_STATUS_SUCCESS;

err:
    if (egress_ctrl->rr) {
        netos_egress_rr_deinit(egress_ctrl->rr);
        free(egress_ctrl->rr);
    }

    return NETOS_STATUS_EGRESS_RR_INIT_FAILED;
}

static void netos_egress_alg_rr_deinit(netos_egress_controller_t *egress_ctrl)
{
    if (egress_ctrl->rr) {
        free(egress_ctrl->rr);
    }
    egress_ctrl->rr = NULL;
}

netos_egress_controller_t *netos_egress_controller_init(netos_raw_socket_ctx_t *raw)
{
    netos_egress_controller_t *egress_ctrl;
    netos_status_t ret;

    egress_ctrl = calloc(1, sizeof(netos_egress_controller_t));
    if (!egress_ctrl) {
        return NULL;
    }

    uint32_t i;

    for (i = 0; i < sizeof(egress_alg_list) / sizeof(egress_alg_list[0]); i ++) {
        ret = egress_alg_list[i].queue_alg_init(egress_ctrl);
        if (ret != NETOS_STATUS_SUCCESS) {
            netos_log_error("Failed to initialize the %s queue\n", egress_alg_list[i].name);
            goto err;
        }
        netos_log_info("Initialized Queue %s\n", egress_alg_list[i].name);
    }

    return egress_ctrl;

err:
    if (egress_ctrl) {
        for (i = 0; i < sizeof(egress_alg_list) / sizeof(egress_alg_list[0]); i ++) {
            egress_alg_list[i].queue_alg_deinit(egress_ctrl);
        }
        free(egress_ctrl);
    }

    return NULL;
}

void netos_egress_enque(netos_egress_controller_t *egress_ctrl,
                        netos_egress_queueing_alg_t alg,
                        pkt_buffer_t *pkt_buf)
{
    // invalid egress algorithm
    if ((alg < NETOS_EGRESS_ALG_SP) || (alg > NETOS_EGRESS_ALG_RR)) {
        egress_ctrl->mib.drops_inval_alg ++;
        return;
    }

    // dispatch the frame to the queueing algorithm
    egress_alg_list[alg].queue_alg_run(egress_alg_list[alg].queue_ctrl_ctx, pkt_buf);
    egress_alg_list[alg].use_count ++;
}

void netos_egress_controller_deinit(netos_egress_controller_t *egress_ctrl)
{
    if (egress_ctrl) {
        for (uint32_t i = 0; i < sizeof(egress_alg_list) / sizeof(egress_alg_list[0]); i ++) {
            egress_alg_list[i].queue_alg_deinit(egress_ctrl);
        }
        free(egress_ctrl);
    }
}

