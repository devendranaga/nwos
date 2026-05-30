#include <stdio.h>
#include <pthread.h>

#include "netos_status.h"
#include "pthread_intf.h"

netos_status_t netos_pthread_create_detached(pthread_t *tid, void *(*thread_cb)(void *), void *cbdata)
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

    return res;

err:
    pthread_attr_destroy(&attr);
    return res;
}