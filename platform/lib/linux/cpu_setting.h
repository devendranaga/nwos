#ifndef PLATFORM_LIB_LINUX_CPU_SETTING_H
#define PLATFORM_LIB_LINUX_CPU_SETTING_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <pthread.h>
#include <sched.h>

/**
 * @brief - Attach thread to the CPU. The scheduler does not schedule it to other core.
 *
 * @param [in] thread_id - Thread id.
 * @param [in] core_no - CPU core number.
 */
inline int netos_set_cpu_affinity(pthread_t thread_id, uint32_t core_no)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(core_no, &cpuset);

    return pthread_setaffinity_np(thread_id, sizeof(cpuset), &cpuset);
}

#if defined(__cplusplus)
}
#endif

#endif

