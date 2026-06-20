#include <stdio.h>
#include "icmp_hdr.h"
#include "pkt_buffer.h"
#include "checksum.h"
#include "event_info.h"
#include "netos_status.h"

#define NETOS_ICMP_TYPE_ECHO_REQ    8
#define NETOS_ICMP_TYPE_ECHO_REPLY  0
#define NETOS_ICMP_CODE_ECHO_REQ    0
#define NETOS_ICMP_CODE_ECHO_REPLY  0

#define NETOS_ICMP_HDR_LEN          4
#define NETOS_ICMP_ECHO_REQ_LEN     4
#define NETOS_ICMP_ECHO_REPLY_LEN   4

static netos_status_t
netos_icmp_decode_echo_request(netos_icmp_hdr_t *icmp_hdr,
                               pkt_buffer_t *pkt_buf)
{
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_ECHO_REQ_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REQ);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_req.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_req.seq_no);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_icmp_decode_echo_reply(netos_icmp_hdr_t *icmp_hdr,
                             pkt_buffer_t *pkt_buf)
{
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_ECHO_REPLY_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REPLY);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_reply.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_reply.seq_no);

    return NETOS_STATUS_SUCCESS;
}

static const struct {
    uint8_t type;
    uint8_t code;
    netos_status_t (*encode)(netos_icmp_hdr_t *icmp_hdr,
                             pkt_buffer_t *pkt_buf);
    netos_status_t (*decode)(netos_icmp_hdr_t *icmp_hdr,
                             pkt_buffer_t *pkt_buf);
} netos_icmp_callbacks[] = {
    {
        NETOS_ICMP_TYPE_ECHO_REQ,
        NETOS_ICMP_CODE_ECHO_REQ,
        NULL,
        netos_icmp_decode_echo_request
    },
    {
        NETOS_ICMP_TYPE_ECHO_REPLY,
        NETOS_ICMP_CODE_ECHO_REPLY,
        NULL,
        netos_icmp_decode_echo_reply
    }
};

netos_status_t netos_icmp_decode(netos_icmp_hdr_t *icmp_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    uint32_t i;

    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_HDR_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REQ);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    icmp_hdr->start_off = pkt_buf->offset;

    pkt_buffer_decode_byte(pkt_buf, &icmp_hdr->type);
    pkt_buffer_decode_byte(pkt_buf, &icmp_hdr->code);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->checksum);

    for (i = 0; i < sizeof(netos_icmp_callbacks) / sizeof(netos_icmp_callbacks[0]); i ++) {
        if ((icmp_hdr->type == netos_icmp_callbacks[i].type) &&
            (icmp_hdr->code == netos_icmp_callbacks[i].code)) {
            ret = netos_icmp_callbacks[i].decode(icmp_hdr, pkt_buf);
            if (ret != NETOS_STATUS_SUCCESS) {
                return ret;
            }

            netos_checksum_t chksum_info = {
                .buffer = &(pkt_buf->buffer[icmp_hdr->start_off]),
                .len = pkt_buf->rx_len - icmp_hdr->start_off,
            };
            uint16_t chksum;

            chksum = netos_icmp_checksum(&chksum_info);
            printf("%x\n", chksum);
        }
    }

    return NETOS_STATUS_SUCCESS;
}

