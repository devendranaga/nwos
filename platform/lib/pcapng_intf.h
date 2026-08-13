#ifndef NETOS_PCAPNG_INTF_H
#define NETOS_PCAPNG_INTF_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t    original_len;
    uint32_t    captured_len;
    uint8_t     *pkt;
} netos_pcapng_frame_t;

typedef struct {
    bool is_ipv4;
    union {
        uint32_t ipaddr;
        uint8_t ip6addr[16];
    } bytes;
    char *ipaddr_str;
} netos_pcapng_dns_lookup_data_t;

#define NETOS_DNS_LOOKUP_DATA_INIT(__data) do {\
    (__data).is_ipv4 = false;\
    (__data).bytes.ipaddr = 0;\
    (__data).bytes.ip6addr[0] = 0;\
    (__data).bytes.ip6addr[1] = 0;\
    (__data).bytes.ip6addr[2] = 0;\
    (__data).bytes.ip6addr[3] = 0;\
    (__data).bytes.ip6addr[4] = 0;\
    (__data).bytes.ip6addr[5] = 0;\
    (__data).bytes.ip6addr[6] = 0;\
    (__data).bytes.ip6addr[7] = 0;\
    (__data).bytes.ip6addr[8] = 0;\
    (__data).bytes.ip6addr[9] = 0;\
    (__data).bytes.ip6addr[10] = 0;\
    (__data).bytes.ip6addr[11] = 0;\
    (__data).bytes.ip6addr[12] = 0;\
    (__data).bytes.ip6addr[13] = 0;\
    (__data).bytes.ip6addr[14] = 0;\
    (__data).bytes.ip6addr[15] = 0;\
    (__data).ipaddr_str = NULL;\
} while (0)

typedef void (*netos_pcapng_parse_cb)(void *ctx, netos_pcapng_frame_t *frame);
typedef void (*netos_pcapng_dns_lookup_cb)(void *ctx, netos_pcapng_dns_lookup_data_t *dns_data);

typedef struct {
    netos_pcapng_parse_cb       parse_cb;
    netos_pcapng_dns_lookup_cb  dns_cb;
} netos_pcapng_parse_callbacks_t;

/**
 * @brief - Parse a pcapng file.
 *
 * @param [in] op - pcap operation.
 * @param [in] filename - pcap filename.
 * @param [in] ctx - user's context.
 * @param [in] parse_cb - callbacks that get called when a frame is parsed.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
netos_status_t netos_pcapng_ctx_parse(const char *filename,
                                      void *ctx,
                                      netos_pcapng_parse_callbacks_t *parse_cb);

#endif

