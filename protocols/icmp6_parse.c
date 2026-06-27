#include "netos_status.h"
#include "pkt_buffer.h"
#include "icmp6_hdr.h"

static netos_status_t netos_icmp6_decode_echo_req(netos_icmp6_hdr_t *icmp6_hdr,
                                                  pkt_buffer_t *pkt_buf)
{
    uint16_t remaining_len;

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp6_hdr->u.echo_req.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp6_hdr->u.echo_req.seq_no);

    remaining_len = pkt_buffer_remaining_rx_len(pkt_buf);
    icmp6_hdr->u.echo_req.data_len = remaining_len;
    if (remaining_len != 0) {
        icmp6_hdr->u.echo_req.data = &pkt_buf->buffer[pkt_buf->offset];
    } else {
        icmp6_hdr->u.echo_req.data = NULL;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t netos_icmp6_decode_echo_reply(netos_icmp6_hdr_t *icmp6_hdr,
                                                    pkt_buffer_t *pkt_buf)
{
    uint16_t remaining_len;

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp6_hdr->u.echo_reply.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp6_hdr->u.echo_reply.seq_no);

    remaining_len = pkt_buffer_remaining_rx_len(pkt_buf);
    icmp6_hdr->u.echo_reply.data_len = remaining_len;
    if (remaining_len != 0) {
        icmp6_hdr->u.echo_reply.data = &pkt_buf->buffer[pkt_buf->offset];
    } else {
        icmp6_hdr->u.echo_reply.data = NULL;
    }

    return NETOS_STATUS_SUCCESS;
}

static const struct {
    uint8_t type;
    uint8_t code;
    netos_status_t (*encode_callback)(netos_icmp6_hdr_t *icmp6_hdr,
                                      pkt_buffer_t *pkt_buf);
    netos_status_t (*decode_callback)(netos_icmp6_hdr_t *icmp6_hdr,
                                      pkt_buffer_t *pkt_buf);
} netos_icmp6_callbacks[] = {
    {
        NETOS_ICMP6_TYPE_ECHO_REQ,
        NETOS_ICMP6_CODE_ECHO_REQ,
        NULL,
        netos_icmp6_decode_echo_req
    },
    {
        NETOS_ICMP6_TYPE_ECHO_REPLY,
        NETOS_ICMP6_CODE_ECHO_REPLY,
        NULL,
        netos_icmp6_decode_echo_reply
    }
};

netos_status_t netos_icmp6_decode(netos_icmp6_hdr_t *icmp6_hdr,
                                  pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_ICMP6_MALFORMED_PKT;
    uint32_t i;

    pkt_buffer_decode_byte(pkt_buf, &icmp6_hdr->type);
    pkt_buffer_decode_byte(pkt_buf, &icmp6_hdr->code);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp6_hdr->checksum);

    for (i = 0; i < sizeof(netos_icmp6_callbacks) /
                    sizeof(netos_icmp6_callbacks[0]); i ++) {
        if ((netos_icmp6_callbacks[i].type == icmp6_hdr->type) &&
            (netos_icmp6_callbacks[i].code == icmp6_hdr->code)) {
            if (netos_icmp6_callbacks[i].decode_callback) {
                ret = netos_icmp6_callbacks[i].decode_callback(icmp6_hdr, pkt_buf);
                break;
            }
        }
    }

    return ret;
}

