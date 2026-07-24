#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netos_status.h"
#include "netos_config.h"
#include "egress_sp.h"
#include "egress_rr.h"
#include "egress_controller.h"
#include "netos_log.h"

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

    return NETOS_STATUS_SUCCESS;

err:
    if (egress_ctrl->sp) {
        free(egress_ctrl->sp);
        egress_ctrl->sp = NULL;
    }

    return NETOS_STATUS_EGRESS_SP_INIT_FAILED;
}

static void netos_egress_alg_sp_deinit(netos_egress_controller_t *egress_ctrl)
{
    netos_egress_sp_deinit(egress_ctrl->sp);
    free(egress_ctrl->sp);
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

    return NETOS_STATUS_SUCCESS;

err:
    if (egress_ctrl->rr) {
        netos_egress_rr_deinit(egress_ctrl->rr);
        free(egress_ctrl->rr);
        egress_ctrl->rr = NULL;
    }

    return NETOS_STATUS_EGRESS_RR_INIT_FAILED;
}

static void netos_egress_alg_rr_deinit(netos_egress_controller_t *egress_ctrl)
{
    netos_egress_rr_deinit(egress_ctrl->rr);
    free(egress_ctrl->rr);
    egress_ctrl->rr = NULL;
}

static netos_status_t netos_egress_alg_pfifo_init(netos_egress_controller_t *egress_ctrl)
{
    netos_status_t ret;

    egress_ctrl->pfifo = calloc(1, sizeof(netos_egress_pfifo_mgr_t));
    if (!egress_ctrl->pfifo) {
        goto err;
    }

    ret = netos_egress_pfifo_init(egress_ctrl->pfifo,
                                  egress_ctrl->config->egress_ctrl.pfifo.max_pkts);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    return NETOS_STATUS_SUCCESS;

err:
    if (egress_ctrl->pfifo) {
        netos_egress_pfifo_deinit(egress_ctrl->pfifo);
        free(egress_ctrl->pfifo);
        egress_ctrl->pfifo = NULL;
    }

    return NETOS_STATUS_EGRESS_PFIFO_INIT_FAILED;
}

static void netos_egress_alg_pfifo_deinit(netos_egress_controller_t *egress_ctrl)
{
    netos_egress_pfifo_deinit(egress_ctrl->pfifo);
    free(egress_ctrl->pfifo);
    egress_ctrl->pfifo = NULL;
}

netos_egress_controller_t *
netos_egress_controller_init(netos_raw_socket_ctx_t *raw,
                             network_config_t *config)
{
    netos_egress_controller_t *egress_ctrl;
    netos_status_t ret;

    egress_ctrl = calloc(1, sizeof(netos_egress_controller_t));
    if (!egress_ctrl) {
        return NULL;
    }

    egress_ctrl->config = config;

    ret = netos_egress_alg_sp_init(egress_ctrl);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    ret = netos_egress_alg_rr_init(egress_ctrl);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    ret = netos_egress_alg_pfifo_init(egress_ctrl);
    if (ret != NETOS_STATUS_SUCCESS) {
        goto err;
    }

    return egress_ctrl;

err:
    if (egress_ctrl) {
        if (egress_ctrl->sp) {
            netos_egress_alg_sp_deinit(egress_ctrl);
        }
        if (egress_ctrl->rr) {
            netos_egress_alg_rr_deinit(egress_ctrl);
        }
        if (egress_ctrl->pfifo) {
            netos_egress_alg_pfifo_deinit(egress_ctrl);
        }
    }

    return NULL;
}

void netos_egress_enque(netos_egress_controller_t *egress_ctrl,
                        netos_egress_queueing_alg_t alg,
                        pkt_buffer_t *pkt_buf)
{
    // invalid egress algorithm
    if ((alg < NETOS_EGRESS_ALG_SP) || (alg > NETOS_EGRESS_ALG_PFIFO)) {
        egress_ctrl->mib.drops_inval_alg ++;
        return;
    }

    // dispatch the frame to the queueing algorithm
    switch (alg) {
        case NETOS_EGRESS_ALG_SP:
            if (egress_ctrl->sp) {
                netos_egress_sp_enque(egress_ctrl->sp, pkt_buf);
            }
        break;
        case NETOS_EGRESS_ALG_RR:
            if (egress_ctrl->rr) {
                netos_egress_rr_enque(egress_ctrl->rr, pkt_buf);
            }
        break;
        case NETOS_EGRESS_ALG_PFIFO:
            if (egress_ctrl->pfifo) {
                netos_egress_pfifo_enque(egress_ctrl->pfifo, pkt_buf);
            }
        break;
        default:
            return;
    }
}

void netos_egress_controller_deinit(netos_egress_controller_t *egress_ctrl)
{
    if (egress_ctrl->sp) {
        netos_egress_sp_deinit(egress_ctrl->sp);
    }
    if (egress_ctrl->rr) {
        netos_egress_rr_deinit(egress_ctrl->rr);
    }
    if (egress_ctrl->pfifo) {
        netos_egress_pfifo_deinit(egress_ctrl->pfifo);
    }
}

