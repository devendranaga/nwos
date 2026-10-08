#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "netos_status.h"
#include "netos_log.h"

bool netos_is_unix_socket_active(const char *socket_path)
{
    char line[512];
    bool is_active = false;
    FILE *fp;

    if (access(socket_path, F_OK) == -1) {
        if (errno == ENOENT) {
            return false;
        }
        return true;
    }

    fp = fopen("/proc/net/unix", "r");
    if (!fp) {
        netos_log_error("failed to open /proc/net/unix\n");
        return false;
    }


    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;

        char *match = strstr(line, socket_path);
        if (match) {
            if (strcmp(match, socket_path) == 0) {
                is_active = true;
                break;
            }
        }
    }

    fclose(fp);
    return is_active;
}

