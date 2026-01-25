#ifndef NETOS_LOGGING_PROTOCOL_H
#define NETOS_LOGGING_PROTOCOL_H

#include <arpa/inet.h>
#include <netinet/in.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define NETOS_LOG_LEVEL_VERBOSE 0
#define NETOS_LOG_LEVEL_INFO 1
#define NETOS_LOG_LEVEL_DEBUG 2
#define NETOS_LOG_LEVEL_WARNING 3
#define NETOS_LOG_LEVEL_ERROR 4

struct netos_log_info {
#define LOGI_STR 0x4C4F4749
    uint32_t log_msg_str; // LOGI
#define LOG_VERSION 1
    uint8_t version;
    uint8_t log_level;
    uint16_t data_len;
    uint64_t ts_sec;
    uint64_t ts_nsec;
    uint8_t data[0];
} __attribute__ ((__packed__));

#define LOG_MSG_PREPARE(__log_info, __level, __ts_sec, __ts_nsec, __data_len) { \
    __log_info->log_msg_str = ntohl(LOGI_STR); \
    __log_info->version = LOG_VERSION; \
    __log_info->log_level = __level; \
    __log_info->ts_sec = __ts_sec; \
    __log_info->ts_nsec = __ts_nsec; \
    __log_info->data_len = __data_len; \
}

#if defined(__cplusplus)
}
#endif

#endif

