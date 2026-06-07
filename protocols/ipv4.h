#ifndef NETOS_PROTOCOLS_IPV4_H
#define NETOS_PROTOCOLS_IPV4_H

#if defined(__cplusplus)
extern "C" {
#endif

#define NETOS_IPV4_VERSION          4
#define NETOS_IPV4_HDR_LEN_DEFAULT  20
#define NETOS_IPV4_HDR_LEN_MAX      60

typedef struct __attribute__ ((__packed__)) {
    uint8_t     reseved             :1;
    uint8_t     dont_fragment       :1;
    uint8_t     more_fragment       :1;
    uint16_t    frag_off            :13;
} netos_ipv4_flags_t;

typedef struct netos_ipv4_hdr {
    uint8_t             version         :4;
    uint8_t             header_len      :4;
    uint8_t             dscp            :6;
    uint8_t             ecn             :2;
    uint16_t            total_len;
    uint16_t            identification;
    netos_ipv4_flags_t  flags;
    uint8_t             ttl;
    uint8_t             protocol;
    uint16_t            hdr_chksum;
    uint32_t            src_ipaddr;
    uint32_t            dst_ipaddr;
} netos_ipv4_hdr_t;

netos_status_t netos_ipv4_decode(netos_ipv4_hdr_t *ipv4_hdr, pkt_buffer_t *pkt_buf);

#if defined(__cplusplus)
}
#endif

#endif

