#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "unix_intf.h"

int netos_unix_intf_udp_server_socket_init(const char *path)
{
    struct sockaddr_un serv_info;
    int fd;
    int ret;

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    unlink(path);
    memset(&serv_info, 0, sizeof(serv_info));
    serv_info.sun_family = AF_UNIX;
    strncpy(serv_info.sun_path, path, sizeof(serv_info.sun_path) - 1);

    ret = bind(fd, (struct sockaddr *)&serv_info, sizeof(serv_info));
    if (ret < 0) {
        goto err;
    }

    return fd;

err:
    if (fd >= 0) {
        close(fd);
    }

    return -1;
}

int netos_unix_intf_udp_send(int fd,
                             const char *path,
                             const uint8_t *msg,
                             uint32_t msg_len)
{
    struct sockaddr_un sender_info;

    memset(&sender_info, 0, sizeof(sender_info));
    sender_info.sun_family = AF_UNIX;
    strncpy(sender_info.sun_path, path, sizeof(sender_info.sun_path) - 1);

    return sendto(fd, msg, msg_len, 0,
                  (struct sockaddr *)&sender_info, sizeof(sender_info));
}

int netos_unix_intf_udp_recv(int fd,
                             char *path,
                             uint32_t path_len,
                             uint8_t *msg,
                             uint32_t msg_len)
{
    struct sockaddr_un recv_info;
    socklen_t recv_info_len;
    size_t n = 0;
    int ret;

    if (!path || (path_len == 0)) {
        return -1;
    }

    memset(&recv_info, 0, sizeof(recv_info));
    recv_info.sun_family = AF_UNIX;
    recv_info_len = sizeof(recv_info);

    ret = recvfrom(fd, msg, msg_len, 0,
                   (struct sockaddr *)&recv_info, &recv_info_len);
    if (ret < 0) {
        return -1;
    }

    if (recv_info_len > offsetof(struct sockaddr_un, sun_path)) {
        n = recv_info_len - offsetof(struct sockaddr_un, sun_path);
    }
    n = strnlen(recv_info.sun_path, n);
    if (n > (size_t)path_len - 1) {
        n = path_len - 1;
    }

    memcpy(path, recv_info.sun_path, n);
    path[n] = '\0';

    return ret;
}

void netos_unix_intf_udp_close(int fd, const char *path)
{
    if (fd >= 0) {
        close(fd);
    }
    if (path) {
        unlink(path);
    }
}

