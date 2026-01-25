#ifndef NETOS_PLATFORM_LIB_LOGGING_LOGGING_H
#define NETOS_PLATFORM_LIB_LOGGING_LOGGING_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>

void netos_log_verbose(const char *fmt, ...);
void netos_log_info(const char *fmt, ...);
void netos_log_debug(const char *fmt, ...);
void netos_log_warning(const char *fmt, ...);
void netos_log_error(const char *fmt, ...);

int netos_log_init(const char *server_ip, uint16_t server_port);
void netos_log_deinit();

#if defined(__cplusplus)
}
#endif

#endif

