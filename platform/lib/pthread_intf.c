#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#include "netos_status.h"
#include "pthread_intf.h"
#include "cpu_affinity.h"

netos_status_t netos_pthread_create_detached(pthread_t *tid, int cpu_id, void *(*thread_cb)(void *), void *cbdata)
{
    pthread_attr_t attr;
    netos_status_t res = NETOS_STATUS_SUCCESS;
    int ret;

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        return NETOS_STATUS_PTHREAD_ATTR_INIT_FAILED;
    }

    ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (ret != 0) {
        res = NETOS_STATUS_PTHREAD_DETACH_FAILED;
        goto err;
    }

    ret = pthread_create(tid, &attr, thread_cb, cbdata);
    if (ret != 0) {
        res = NETOS_STATUS_PTHREAD_INIT_FAILED;
        goto err;
    }

    ret = netos_attach_thread_to_cpu(cpu_id, tid);
    if (ret != NETOS_STATUS_SUCCESS) {
        // cannot attach the thread to a specific CPU
        // let the OS decide here what it needs to do with the thread scheduling
        res = NETOS_STATUS_SUCCESS;
    }

    return res;

err:
    pthread_attr_destroy(&attr);
    return res;
}
