#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

pthread_mutex_t lock;

typedef enum {
    NETOS_LOG_TYPE_VERBOSE = 0,
    NETOS_LOG_TYPE_INFO    = 1,
    NETOS_LOG_TYPE_DEBUG   = 2,
    NETOS_LOG_TYPE_WARNING = 3,
    NETOS_LOG_TYPE_ERROR   = 4,
} netos_log_type_t;

const char *log_msg_type_list[] = {
    "verbose",
    "info",
    "debug",
    "warning",
    "error",
};

static void netos_log_msg(netos_log_type_t type, const char *fmt, va_list ap)
{
    struct timespec tp;
    char buf[4096];
    struct tm *t;
    time_t now;
    int ret;

    now = time(0);
    t = gmtime(&now);
    clock_gettime(CLOCK_REALTIME, &tp);

    pthread_mutex_lock(&lock);
    ret = snprintf(buf, sizeof(buf), "[%04d-%02d-%02d %02d-%02d-%02d.%04lld] <%s> ",
                            t->tm_year + 1900,
                            t->tm_mon + 1,
                            t->tm_mday,
                            t->tm_hour,
                            t->tm_min,
                            t->tm_sec,
                            tp.tv_nsec / 1000000ULL,
                            log_msg_type_list[type]);
    ret += vsnprintf(buf + ret, sizeof(buf) - ret, fmt, ap);
    fprintf(stderr, "%s\n", buf);
    pthread_mutex_unlock(&lock);
}

void netos_log_verbose(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_msg(NETOS_LOG_TYPE_VERBOSE, fmt, ap);
    va_end(ap);
}

void netos_log_info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_msg(NETOS_LOG_TYPE_INFO, fmt, ap);
    va_end(ap);
}

void netos_log_debug(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_msg(NETOS_LOG_TYPE_DEBUG, fmt, ap);
    va_end(ap);
}

void netos_log_warning(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_msg(NETOS_LOG_TYPE_WARNING, fmt, ap);
    va_end(ap);
}

void netos_log_error(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    netos_log_msg(NETOS_LOG_TYPE_ERROR, fmt, ap);
    va_end(ap);
}

