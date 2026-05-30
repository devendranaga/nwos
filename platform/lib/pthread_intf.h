#ifndef NETOS_PTHREAD_INTF_H
#define NETOS_PTHREAD_INTF_H

netos_status_t netos_pthread_create_detached(pthread_t *tid, void *(*thread_cb)(void *), void *cbdata);

#endif
