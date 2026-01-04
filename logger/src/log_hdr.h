#ifndef NETOS_LOG_HDR_H
#define NETOS_LOG_HDR_H

#if defined(__cplusplus)
extern "C" {
#endif

#define NETOS_LOG_LEVEL_VERBOSE 0
#define NETOS_LOG_LEVEL_INFO 1
#define NETOS_LOG_LEVEL_DEBUG 2
#define NETOS_LOG_LEVEL_WARNING 3
#define NETOS_LOG_LEVEL_ERROR 4

struct netos_log_info {
    uint32_t log_level;
    uint8_t msg[1024];
};

#if defined(__cplusplus)
}
#endif

#endif

