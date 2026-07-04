#ifndef NETOS_CPU_AFFINITY_H
#define NETOS_CPU_AFFINITY_H

#if defined(__cplusplus)
extern "C" {
#endif

int netos_get_num_cpu();

netos_status_t netos_attach_thread_to_cpu(uint32_t cpu_no, pthread_t *tid);

#if defined(__cplusplus)
}
#endif

#endif

