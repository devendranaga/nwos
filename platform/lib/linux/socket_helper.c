#include <stdint.h>
#include <sys/socket.h>

#include "socket_helper.h"

int set_socket_reuse(int fd)
{
    uint32_t reuse = 1;

    return setsockopt(fd,
                      SOL_SOCKET,
                      SO_REUSEADDR,
                      &reuse,
                      sizeof(reuse));
}
