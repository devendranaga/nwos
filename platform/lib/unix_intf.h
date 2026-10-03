#ifndef NETOS_UNIX_INTF_H
#define NETOS_UNIX_INTF_H

int netos_unix_intf_udp_server_socket_init(const char *path);

int netos_unix_intf_udp_send(int fd, const char *path, const uint8_t *msg, uint32_t msg_len);

int netos_unix_intf_udp_recv(int fd, char *path, uint8_t *msg, uint32_t msg_len);

#endif

