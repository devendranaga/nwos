#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <syslog.h>
#include "netos_config.h"
#include "netos_status.h"
#include "common.h"
#include "netos_log.h"

static pthread_mutex_t lock;
static bool enable_syslog = false;

static const char *log_level_table[] = {
    "",
    "Info",
    "Debug",
    "Warn",
    "Error"
};

static inline const char *netos_log_level_str(netos_log_level_t log_level)
{
    const char *log_level_str = "Unknown";

    if (log_level >= NETOS_SIZEOF_ARRAY(log_level_table)) {
        return log_level_str;
    }

    return log_level_table[log_level];
}

static inline uint32_t netos_log_level_to_syslog(netos_log_level_t log_level)
{
    switch (log_level) {
        case NETOS_LOG_LEVEL_INFO:
            return LOG_INFO;
        break;
        case NETOS_LOG_LEVEL_WARN:
            return LOG_WARNING;
        break;
        case NETOS_LOG_LEVEL_DEBUG:
            return LOG_DEBUG;
        break;
        case NETOS_LOG_LEVEL_ERROR:
            return LOG_ERR;
        break;
        default:
            return LOG_INFO;
    }
}

void netos_log_init(netos_config_t *config)
{
    pthread_mutex_init(&lock, NULL);

    enable_syslog = config->log_config.enable_syslog;
    if (enable_syslog) {
        openlog("netosd", LOG_PID, LOG_USER);
    }
}

static void netos_log_internal(const char *fmt, netos_log_level_t log_level, va_list ap)
{
    char msg[2048];
    int ret;
    time_t now;
    struct tm *t;
    struct timespec tp;

    pthread_mutex_lock(&lock);

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &tp);

    ret = snprintf(msg, sizeof(msg), "[%04d-%02d-%02d %02d:%02d:%02d.%04lld <%s>] ",
                                     t->tm_year + 1900,
                                     t->tm_mon + 1,
                                     t->tm_mday,
                                     t->tm_hour,
                                     t->tm_min,
                                     t->tm_sec,
                                     tp.tv_nsec / 1000000ull,
                                     netos_log_level_str(log_level));

    ret += vsnprintf(msg + ret, sizeof(msg) - ret, fmt, ap);
    fprintf(stderr, "%s", msg);

    if (enable_syslog) {
        syslog(netos_log_level_to_syslog(log_level), "%s", msg);
    }

    pthread_mutex_unlock(&lock);
}

void netos_log_info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_internal(fmt, NETOS_LOG_LEVEL_INFO, ap);
    va_end(ap);
}

void netos_log_debug(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_internal(fmt, NETOS_LOG_LEVEL_DEBUG, ap);
    va_end(ap);
}

void netos_log_warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_internal(fmt, NETOS_LOG_LEVEL_WARN, ap);
    va_end(ap);
}

void netos_log_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_internal(fmt, NETOS_LOG_LEVEL_ERROR, ap);
    va_end(ap);
}

