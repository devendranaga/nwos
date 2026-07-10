#ifndef NETOS_EGRESS_CONTROLLER_H
#define NETOS_EGRESS_CONTROLLER_H

#include "raw_socket.h"
#include "egress_sp.h"
#include "egress_rr.h"
#include "egress_pfifo.h"

typedef enum {
    NETOS_EGRESS_ALG_SP = 0, // Strict priority 8 queues
    NETOS_EGRESS_ALG_RR,     // Round robin 8 queues
    NETOS_EGRESS_ALG_PFIFO,  // packet fifo single queue
    NETOS_EGRESS_ALG_WRR,    // Weighted round robin <not implemented>
} netos_egress_queueing_alg_t;

typedef struct netos_egress_controller_mib {
    uint64_t drops_inval_alg;
} netos_egress_controller_mib_t;

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
    char                            *ifname;
    netos_raw_socket_ctx_t          *raw;
    netos_egress_sp_mgr_t           *sp;
    netos_egress_rr_mgr_t           *rr;
    netos_egress_pfifo_mgr_t        *pfifo;
    netos_egress_controller_mib_t   mib;
} netos_egress_controller_t;

netos_egress_controller_t *netos_egress_controller_init(netos_raw_socket_ctx_t *raw);

void netos_egress_enque(netos_egress_controller_t *egress_ctrl,
                        netos_egress_queueing_alg_t alg,
                        pkt_buffer_t *pkt_buf);

void netos_egress_controller_deinit(netos_egress_controller_t *egress_ctrl);

#endif
