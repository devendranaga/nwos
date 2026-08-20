#include <stdio.h>
#include "icmp_hdr.h"
#include "pkt_buffer.h"
#include "common.h"
#include "checksum.h"
#include "event_info.h"
#include "netos_status.h"

/**
 * @brief - Decode Echo request.
 *
 * @param [inout] icmp_hdr - ICMP header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
static netos_status_t
netos_icmp_decode_echo_request(netos_icmp_hdr_t *icmp_hdr,
                               pkt_buffer_t *pkt_buf)
{
    // short header length check for echo request
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_ECHO_REQ_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REQ);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_req.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_req.seq_no);
    icmp_hdr->u.echo_req.data_len = pkt_buffer_remaining_rx_len(pkt_buf);

    // if there is more data in the icmp request, set the data pointer.
    if (icmp_hdr->u.echo_req.data_len != 0) {
        icmp_hdr->u.echo_req.data = &pkt_buf->buffer[pkt_buf->offset];
    }

    return NETOS_STATUS_SUCCESS;
}

/**
 * @brief - Decode Echo reply.
 *
 * @param [inout] icmp_hdr - ICMP header.
 * @param [inout] pkt_buf - packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
static netos_status_t
netos_icmp_decode_echo_reply(netos_icmp_hdr_t *icmp_hdr,
                             pkt_buffer_t *pkt_buf)
{
    // short header length check for echo reply
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_ECHO_REPLY_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REPLY);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_reply.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.echo_reply.seq_no);
    icmp_hdr->u.echo_reply.data_len = pkt_buffer_remaining_rx_len(pkt_buf);

    // if there is more data in the icmp reply, set the data pointer.
    if (icmp_hdr->u.echo_reply.data_len != 0) {
        icmp_hdr->u.echo_reply.data = &pkt_buf->buffer[pkt_buf->offset];
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_icmp_decode_dest_unreachable_common(netos_icmp_hdr_t *icmp_hdr,
                                          pkt_buffer_t *pkt_buf)
{
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_DEST_UNREACH_LEN)) {
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    pkt_buffer_decode_4_bytes(pkt_buf, &icmp_hdr->u.dest_unreach.unused);
    icmp_hdr->u.dest_unreach.data_len = pkt_buffer_remaining_rx_len(pkt_buf);

    if (icmp_hdr->u.dest_unreach.data_len != 0) {
        icmp_hdr->u.dest_unreach.data = &pkt_buf->buffer[pkt_buf->offset];
    }

    return NETOS_STATUS_SUCCESS;
}

/**
 * @brief - Encode timestamp request.
 *
 * @param [inout] icmp_hdr - ICMP header.
 * @param [inout] pkt_buf - Packet buffer.
 *
 * @return NETOS_STATUS_SUCCESS on success and error code on failure.
 */
static netos_status_t
netos_icmp_encode_timestamp_req(netos_icmp_hdr_t *icmp_hdr,
                                pkt_buffer_t *pkt_buf)
{
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.ts_req.identifier);
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.ts_req.seq_no);
    pkt_buffer_encode_4_bytes(pkt_buf, icmp_hdr->u.ts_req.originate_ts);
    pkt_buffer_encode_4_bytes(pkt_buf, icmp_hdr->u.ts_req.receive_ts);
    pkt_buffer_encode_4_bytes(pkt_buf, icmp_hdr->u.ts_req.transmit_ts);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_icmp_decode_timestamp_req(netos_icmp_hdr_t *icmp_hdr,
                                pkt_buffer_t *pkt_buf)
{
    // drop if buffer length is short
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_TIMESTAMP_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_TS_REQ);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.ts_req.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.ts_req.seq_no);
    pkt_buffer_decode_4_bytes(pkt_buf, &icmp_hdr->u.ts_req.originate_ts);
    pkt_buffer_decode_4_bytes(pkt_buf, &icmp_hdr->u.ts_req.receive_ts);
    pkt_buffer_decode_4_bytes(pkt_buf, &icmp_hdr->u.ts_req.transmit_ts);

    // generally will not contain extra length, if it has, drop the frame.
    uint16_t remaining_len = pkt_buffer_remaining_rx_len(pkt_buf);
    if (remaining_len != 0) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_TS_REQ_CONTAINS_DATA);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_icmp_decode_timestamp_reply(netos_icmp_hdr_t *icmp_hdr,
                                  pkt_buffer_t *pkt_buf)
{
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_TIMESTAMP_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_TS_REPLY);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.ts_reply.identifier);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->u.ts_reply.seq_no);
    pkt_buffer_decode_4_bytes(pkt_buf, &icmp_hdr->u.ts_reply.originate_ts);
    pkt_buffer_decode_4_bytes(pkt_buf, &icmp_hdr->u.ts_reply.receive_ts);
    pkt_buffer_decode_4_bytes(pkt_buf, &icmp_hdr->u.ts_reply.transmit_ts);

    uint16_t remaining_len = pkt_buffer_remaining_rx_len(pkt_buf);
    if (remaining_len != 0) {
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_icmp_encode_timestamp_reply(netos_icmp_hdr_t *icmp_hdr,
                                  pkt_buffer_t *pkt_buf)
{
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.ts_reply.identifier);
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.ts_reply.seq_no);
    pkt_buffer_encode_4_bytes(pkt_buf, icmp_hdr->u.ts_reply.originate_ts);
    pkt_buffer_encode_4_bytes(pkt_buf, icmp_hdr->u.ts_reply.receive_ts);
    pkt_buffer_encode_4_bytes(pkt_buf, icmp_hdr->u.ts_reply.transmit_ts);

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_icmp_encode_echo_request(netos_icmp_hdr_t *icmp_hdr,
                               pkt_buffer_t *pkt_buf)
{
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.echo_req.identifier);
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.echo_req.seq_no);
    if (icmp_hdr->u.echo_req.data_len != 0) {
        pkt_buffer_encode_bytes(pkt_buf,
                                icmp_hdr->u.echo_req.data,
                                icmp_hdr->u.echo_req.data_len);
    }

    return NETOS_STATUS_SUCCESS;
}

static netos_status_t
netos_icmp_encode_echo_reply(netos_icmp_hdr_t *icmp_hdr,
                             pkt_buffer_t *pkt_buf)
{
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.echo_reply.identifier);
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->u.echo_reply.seq_no);
    if (icmp_hdr->u.echo_reply.data_len != 0) {
        pkt_buffer_encode_bytes(pkt_buf,
                                icmp_hdr->u.echo_reply.data,
                                icmp_hdr->u.echo_reply.data_len);
    }

    return NETOS_STATUS_SUCCESS;
}

/**
 * @brief - defines a list of callbacks for encode and decode
*           a list of icmp types and icmp codes.
*/
static const struct {
    uint8_t         type;
    uint8_t         code;
    netos_status_t  (*encode)(netos_icmp_hdr_t *icmp_hdr,
                              pkt_buffer_t *pkt_buf);
    netos_status_t  (*decode)(netos_icmp_hdr_t *icmp_hdr,
                              pkt_buffer_t *pkt_buf);
} netos_icmp_callbacks[] = {
    {
        NETOS_ICMP_TYPE_DEST_UNREACH,
        NETOS_ICMP_CODE_NW_UNREACH,
        NULL,
        netos_icmp_decode_dest_unreachable_common,
    },
    {
        NETOS_ICMP_TYPE_DEST_UNREACH,
        NETOS_ICMP_CODE_HOST_UNREACH,
        NULL,
        netos_icmp_decode_dest_unreachable_common,
    },
    {
        NETOS_ICMP_TYPE_DEST_UNREACH,
        NETOS_ICMP_CODE_PROT_UNREACH,
        NULL,
        netos_icmp_decode_dest_unreachable_common,
    },
    {
        NETOS_ICMP_TYPE_ECHO_REQ,
        NETOS_ICMP_CODE_ECHO_REQ,
        netos_icmp_encode_echo_request,
        netos_icmp_decode_echo_request
    },
    {
        NETOS_ICMP_TYPE_ECHO_REPLY,
        NETOS_ICMP_CODE_ECHO_REPLY,
        netos_icmp_encode_echo_reply,
        netos_icmp_decode_echo_reply
    },
    {
        NETOS_ICMP_TYPE_TIMESTAMP_REQ,
        NETOS_ICMP_CODE_TIMESTAMP_REQ,
        netos_icmp_encode_timestamp_req,
        netos_icmp_decode_timestamp_req
    },
    {
        NETOS_ICMP_TYPE_TIMESTAMP_REPLY,
        NETOS_ICMP_CODE_TIMESTAMP_REPLY,
        netos_icmp_encode_timestamp_reply,
        netos_icmp_decode_timestamp_reply
    }
};

netos_status_t netos_icmp_decode(netos_icmp_hdr_t *icmp_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;
    uint32_t i;
    uint16_t start_off;

    // check for short header length
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_ICMP_HDR_LEN)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_ICMP_SHORT_ECHO_REQ);
        return NETOS_STATUS_ICMP_MALFORMED_PKT;
    }

    start_off = pkt_buf->offset;

    pkt_buffer_decode_byte(pkt_buf, &icmp_hdr->type);
    pkt_buffer_decode_byte(pkt_buf, &icmp_hdr->code);
    pkt_buffer_decode_2_bytes(pkt_buf, &icmp_hdr->checksum);

    /**
     * match type and code in the list of supported callbacks and call them.
     */
    for (i = 0; i < NETOS_SIZEOF_ARRAY(netos_icmp_callbacks); i ++) {
        if ((icmp_hdr->type == netos_icmp_callbacks[i].type) &&
            (icmp_hdr->code == netos_icmp_callbacks[i].code) &&
            (netos_icmp_callbacks[i].decode)) {
            ret = netos_icmp_callbacks[i].decode(icmp_hdr, pkt_buf);
            if (ret != NETOS_STATUS_SUCCESS) {
                // the events already raised in the callbacks, nothing do to here.
                return ret;
            }

            // prepare checksum
            netos_checksum_t chksum_info = {
                .buffer     = &(pkt_buf->buffer[start_off]),
                .len        = pkt_buf->rx_len - start_off,
            };

            // if checksum not ok, fail
            if (!netos_icmp_verify_checksum(&chksum_info)) {
                NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                           NETOS_EVENT_TYPE_DENY,
                                           NETOS_EVENT_DESC_ICMP_CHECKSUM_VERIFY_FAILED);
                return NETOS_STATUS_ICMP_MALFORMED_PKT;
            }

            // this means the match happened and parser successfully parsed the frame
            break;
        }
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_icmp_encode(netos_icmp_hdr_t *icmp_hdr, pkt_buffer_t *pkt_buf)
{
    uint32_t start_off = 0;
    uint16_t checksum_off = 0;
    netos_status_t ret = NETOS_STATUS_ICMP_MALFORMED_PKT;
    uint32_t i;

    start_off = pkt_buf->offset;

    pkt_buffer_encode_byte(pkt_buf, icmp_hdr->type);
    pkt_buffer_encode_byte(pkt_buf, icmp_hdr->code);

    checksum_off = pkt_buf->offset;
    pkt_buffer_encode_2_bytes(pkt_buf, icmp_hdr->checksum);

    /**
     * match type and code and call the encode callback.
     */
    for (i = 0; i < sizeof(netos_icmp_callbacks) / sizeof(netos_icmp_callbacks[0]); i ++) {
        if ((icmp_hdr->type == netos_icmp_callbacks[i].type) &&
            (icmp_hdr->code == netos_icmp_callbacks[i].code) &&
            (netos_icmp_callbacks[i].encode)) {
            ret = netos_icmp_callbacks[i].encode(icmp_hdr, pkt_buf);
            if (ret != NETOS_STATUS_SUCCESS) {
                return NETOS_STATUS_ICMP_MALFORMED_PKT;
            }

            if (icmp_hdr->gen_checksum) {
                uint32_t checksum;
                netos_checksum_t chksum_info = {
                    .buffer     = &(pkt_buf->buffer[start_off]),
                    .len        = pkt_buf->offset - start_off,
                };

                checksum                            = netos_icmp_checksum(&chksum_info);
                pkt_buf->buffer[checksum_off]       = (checksum & 0xFF00) >> 8;
                pkt_buf->buffer[checksum_off + 1]   = (checksum & 0x00FF);
            }

            break;
        }
    }

    return ret;
}

