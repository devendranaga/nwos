#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#include "netos_status.h"
#include "pthread_intf.h"
#include "cpu_affinity.h"

netos_status_t netos_pthread_create(pthread_t *tid, int cpu_id, void *(*thread_cb)(void *), void *cbdata)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    ret = pthread_create(tid, NULL, thread_cb, cbdata);
    if (ret != 0) {
        return NETOS_STATUS_PTHREAD_INIT_FAILED;
    }

    ret = netos_attach_thread_to_cpu(cpu_id, tid);
    if (ret != NETOS_STATUS_SUCCESS) {
        // cannot attach the thread to a specific CPU
        // let the OS decide here what it needs to do with the thread scheduling
        ret = NETOS_STATUS_SUCCESS;
    }

    return ret;
}
