#ifndef NETOS_PTHREAD_INTF_H
#define NETOS_PTHREAD_INTF_H

/**
 * @brief - Create a detached thread and pin it to a CPU core.
 *
 *          default CPU core is 0.
 *
 * @param [inout] tid - thread id.
 * @param [in] cpu_id - CPU number.
 * @param [in] thread_cb - thread callback.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_pthread_create_detached(pthread_t *tid,
                                             int cpu_id,
                                             void *(*thread_cb)(void *), void *cbdata);

#endif
