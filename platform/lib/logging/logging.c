#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "logging_protocol.h"

typedef enum {
    NETOS_LOG_TYPE_VERBOSE = 0,
    NETOS_LOG_TYPE_INFO    = 1,
    NETOS_LOG_TYPE_DEBUG   = 2,
    NETOS_LOG_TYPE_WARNING = 3,
    NETOS_LOG_TYPE_ERROR   = 4,
} netos_log_type_t;

static const struct log_type_str {
    netos_log_type_t log_type;
    const char *log_type_str;
} log_type_str_list[] = {
    {
        NETOS_LOG_TYPE_VERBOSE,
        "Verbose",
    },
    {
        NETOS_LOG_TYPE_INFO,
        "Info",
    },
    {
        NETOS_LOG_TYPE_DEBUG,
        "Debug",
    },
    {
        NETOS_LOG_TYPE_WARNING,
        "Warning",
    },
    {
        NETOS_LOG_TYPE_ERROR,
        "Error",
    }
};

struct logging_context {
    int server_fd;
    struct sockaddr_in server_addr;
    pthread_mutex_t lock;
};

static struct logging_context ctx;

static void netos_log_msg(netos_log_type_t type, const char *fmt, va_list ap)
{
    struct netos_log_info *log_info;
    struct timespec tp = {0};
    char buf[4096] = {0};
    uint32_t data_len;
    int ret;

    // data length is without the header length
    data_len = sizeof(buf) - sizeof(struct netos_log_info);
    log_info = (struct netos_log_info *)buf;

    clock_gettime(CLOCK_REALTIME, &tp);

    pthread_mutex_lock(&ctx.lock);
    // write to the data portion after the header fields.
    ret = vsnprintf((char *)(log_info->data), data_len, fmt, ap);
    LOG_MSG_PREPARE(log_info, type, tp.tv_sec, tp.tv_nsec, ret);
    pthread_mutex_unlock(&ctx.lock);
    sendto(ctx.server_fd,
           buf,
           sizeof(struct netos_log_info) + ret,
           0,
           (struct sockaddr *)&ctx.server_addr,
           sizeof(ctx.server_addr));
    fprintf(stderr, "<%s>: %s", log_type_str_list[type].log_type_str, (char *)(log_info->data));
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

int netos_log_init(const char *server_ip, uint16_t server_port)
{
    int ret;

    ctx.server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx.server_fd < 0) {
        return -1;
    }

    ctx.server_addr.sin_family = AF_INET;
    ctx.server_addr.sin_port = htons(server_port);
    ret = inet_pton(AF_INET, server_ip, &ctx.server_addr.sin_addr);
    if (ret <= 0) {
        return -1;
    }

    return 0;
}

void netos_log_deinit()
{
    if (ctx.server_fd > 0) {
        close(ctx.server_fd);
    }
}

