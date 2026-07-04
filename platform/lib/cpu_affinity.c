#include <stdio.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include "netos_status.h"
#include "cpu_affinity.h"

int netos_get_num_cpu()
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}

netos_status_t netos_attach_thread_to_cpu(uint32_t cpu_no, pthread_t *tid)
{
    cpu_set_t cpuset;
    int res;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_no, &cpuset);

    res = pthread_setaffinity_np(*tid, sizeof(cpu_set_t), &cpuset);
    if (res != 0) {
        return NETOS_STATUS_PTHREAD_SET_CPU_AFFINITY_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

