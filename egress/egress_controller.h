#ifndef NETOS_EGRESS_CONTROLLER_H
#define NETOS_EGRESS_CONTROLLER_H

#include "raw_socket.h"
#include "egress_sp.h"

typedef enum {
    NETOS_EGRESS_ALG_SP = 1, // Strict priority
} netos_egress_queueing_alg_t;

/**
 * @brief
 *
 *  Egress controller runs per interface.
 *
 *  Based on the following egress queuing discipline, the
 *  egress controller will then queue the frame to that specific qdisc.
 *
 *  Multiple egress qdiscs can be activated during initialization,
 *  and then can be selected for a specific flow.
 */
typedef struct netos_egress_controller {
    char                    *ifname;
    raw_socket_ctx_t        *raw;
    netos_egress_sp_mgr_t   *sp;
} netos_egress_controller_t;

netos_egress_controller_t *netos_egress_controller_init(netos_egress_queueing_alg_t alg,
                                                        raw_socket_ctx_t *raw);

void netos_egress_controller_deinit(netos_egress_controller_t *egress_ctrl);

#endif
