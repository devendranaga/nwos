#ifndef NETOS_LOG_H
#define NETOS_LOG_H

#include <stdarg.h>

typedef enum netos_log_level {
    NETOS_LOG_LEVEL_INFO = 1,
    NETOS_LOG_LEVEL_DEBUG,
    NETOS_LOG_LEVEL_WARN,
    NETOS_LOG_LEVEL_ERROR,
} netos_log_level_t;

void netos_log_info(const char *fmt, ...);
void netos_log_debug(const char *fmt, ...);
void netos_log_warn(const char *fmt, ...);
void netos_log_error(const char *fmt, ...);

#endif

