#ifndef NETOS_LOG_H
#define NETOS_LOG_H

#include <stdarg.h>

/**
 * @brief - Defines Logging level.
 */
typedef enum netos_log_level {
    NETOS_LOG_LEVEL_INFO = 1,
    NETOS_LOG_LEVEL_DEBUG,
    NETOS_LOG_LEVEL_WARN,
    NETOS_LOG_LEVEL_ERROR,
} netos_log_level_t;

// ANSI color code list
#define NETOS_ANSI_COLOR_RED        "\x1b[31m"
#define NETOS_ANSI_COLOR_GREEN      "\x1b[32m"
#define NETOS_ANSI_COLOR_YELLOW     "\x1b[33m"
#define NETOS_ANSI_COLOR_BLUE       "\x1b[34m"
#define NETOS_ANSI_COLOR_MAGENTA    "\x1b[35m"
#define NETOS_ANSI_COLOR_CYAN       "\x1b[36m"
#define NETOS_ANSI_COLOR_RESET      "\x1b[0m"

/**
 * @brief - print error in red.
 *
 * @param [in] fmt - format.
 */
#define NETOS_PRINT_STD_ERROR_COLOR(__fmt, ...) do {\
    fprintf(stderr, \
            NETOS_ANSI_COLOR_RED __fmt NETOS_ANSI_COLOR_RESET, ##__VA_ARGS__);\
} while (0)

/**
 * @brief - print in green.
 *
 * @param [in] fmt - format.
 */
#define NETOS_PRINT_STD_GREEN_COLOR(__fmt, ...) do{\
    fprintf(stderr, \
            NETOS_ANSI_COLOR_GREEN __fmt NETOS_ANSI_COLOR_RESET, ##__VA_ARGS__);\
} while (0)

/**
 * @brief - print in magenta.
 *
 * @param [in] fmt - format.
 */
#define NETOS_PRINT_STD_MAGENTA_COLOR(__fmt, ...) do{\
    fprintf(stderr, \
            NETOS_ANSI_COLOR_MAGENTA __fmt NETOS_ANSI_COLOR_RESET, ##__VA_ARGS__);\
} while (0)

/**
 * @brief - print info message.
 *
 * @param [in] fmt - format string.
 */
void netos_log_info(const char *fmt, ...);

/**
 * @brief - print debug message.
 *
 * @param [in] fmt - format string.
 */
void netos_log_debug(const char *fmt, ...);

/**
 * @brief - print warn message.
 *
 * @param [in] fmt - format string.
 */
void netos_log_warn(const char *fmt, ...);

/**
 * @brief - print error message.
 *
 * @param [in] fmt - format string.
 */
void netos_log_error(const char *fmt, ...);

#endif

