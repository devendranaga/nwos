#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include "netos_status.h"
#include "cpu_affinity.h"
#include "netos_log.h"

static int n_cpus = 0;
static int next_cpu = 0;

int netos_get_num_cpu()
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}

netos_status_t netos_attach_thread_to_cpu(uint32_t cpu_no, pthread_t *tid)
{
    cpu_set_t cpuset;
    int n_cpus;
    int res;

    n_cpus = netos_get_num_cpu();
    CPU_ZERO(&cpuset);

    // the pthread_setaffinity_np fails if the number of cpus
    // on the hardware are less than the ask for example
    // if we are running in a vm or on a single core machines.
    if (cpu_no > ((uint32_t)n_cpus - 1)) {
        netos_log_info("number of available cpus [%d] are less than the asked CPU core [%d] "
                       "setting max cpus to [%d]\n",
                        n_cpus, cpu_no, n_cpus);
        cpu_no = n_cpus - 1;
    }

    CPU_SET(cpu_no, &cpuset);

    res = pthread_setaffinity_np(*tid, sizeof(cpu_set_t), &cpuset);
    if (res != 0) {
        return NETOS_STATUS_PTHREAD_SET_CPU_AFFINITY_FAILED;
    }

    return NETOS_STATUS_SUCCESS;
}

int netos_cpu_sched_init()
{
    n_cpus = sysconf(_SC_NPROCESSORS_ONLN);

    return 0;
}

int netos_cpu_sched_get_cpu_id()
{
    int cpu = next_cpu;

    if (n_cpus != 0) {
        next_cpu = (next_cpu + 1) % n_cpus;
    }

    return cpu;
}

