#ifndef PROTOCOLS_IPV6_H
#define PROTOCOLS_IPV6_H

#if defined(__cpluscplus)
extern "C" {
#endif

#define NETOS_IPV6_HDR_LEN_DEFAULT 40
#define NETOS_IPV6_ADDR_LEN 16

/**
 *
 * |--4 bits-|---6 bits---|--2 bits--|----20 bits--------|
 * | version |    dscp    |   ecn    |    flow lable     |
 * |----------------------------|----------|-------------|
 * |  payload length            |    NH    | Hop Limit   |
 * |-----------------------------------------------------|
 * |                 src ipv6 address                    |
 * |-----------------------------------------------------|
 * |                 dst ipv6 address                    |
 * |-----------------------------------------------------|
 */
typedef struct {
    uint8_t     version     :4;
    uint8_t     dscp        :6;
    uint8_t     ecn         :2;
    uint32_t    flow_lable  :20;
    uint16_t    payload_len;
    uint8_t     nh;
    uint8_t     hop_limit;
    uint8_t     src_ipaddr[NETOS_IPV6_ADDR_LEN];
    uint8_t     dst_ipaddr[NETOS_IPV6_ADDR_LEN];
} netos_ipv6_hdr_t;

/**
 * @brief - Decode IPv6 frame.
 *
 * @param [inout] ipv6_hdr - IPv6 header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error on failure.
 */
netos_status_t netos_ipv6_decode(netos_ipv6_hdr_t *ipv6_hdr,
                                 pkt_buffer_t *pkt_buf);

/**
 * @brief - Print the IPv6 header.
 *
 * @param [in] ipv6_hdr - IPv6 header.
 */
void netos_ipv6_print(netos_ipv6_hdr_t *ipv6_hdr);

#if defined(__cpluscplus)
}
#endif

#endif

