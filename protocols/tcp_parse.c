#include "netos_status.h"
#include "pkt_buffer.h"
#include "tcp_hdr.h"
#include "netos_log.h"
#include "checksum.h"
#include "event_info.h"

static netos_status_t netos_tcp_validate_flags(netos_tcp_hdr_t *tcp_hdr,
                                               pkt_buffer_t *pkt_buf)
{
    if (tcp_hdr->flags.cwr &&
        tcp_hdr->flags.ece &&
        tcp_hdr->flags.urg &&
        tcp_hdr->flags.ack &&
        tcp_hdr->flags.psh &&
        tcp_hdr->flags.rst &&
        tcp_hdr->flags.syn &&
        tcp_hdr->flags.fin) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_TCP_FLAGS_ALL_SET);
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    if ((tcp_hdr->flags.cwr == 0) &&
        (tcp_hdr->flags.ece == 0) &&
        (tcp_hdr->flags.urg == 0) &&
        (tcp_hdr->flags.ack == 0) &&
        (tcp_hdr->flags.psh == 0) &&
        (tcp_hdr->flags.rst == 0) &&
        (tcp_hdr->flags.syn == 0) &&
        (tcp_hdr->flags.fin == 0)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_TCP_FLAGS_ALL_ZERO);
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    if (tcp_hdr->flags.syn && tcp_hdr->flags.fin) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_TCP_FLAGS_SYN_FIN_SET);
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    if (tcp_hdr->flags.syn && tcp_hdr->flags.psh) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_TCP_FLAGS_SYN_PSH_SET);
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    if (tcp_hdr->flags.syn && tcp_hdr->flags.rst) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_TCP_FLAGS_SYN_RST_SET);
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    if (tcp_hdr->flags.psh && tcp_hdr->flags.rst) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_TCP_FLAGS_RST_PSH_SET);
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    return NETOS_STATUS_SUCCESS;
}

netos_status_t netos_tcp_decode(netos_tcp_hdr_t *tcp_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret;

    // short header length check
    if (pkt_buffer_has_short_rx_len(pkt_buf, NETOS_TCP_HDR_LEN_DEFAULT)) {
        NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                   NETOS_EVENT_TYPE_DENY,
                                   NETOS_EVENT_DESC_TCP_SHORT_HDR_LEN);
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    pkt_buffer_decode_2_bytes(pkt_buf, &tcp_hdr->src_port);
    pkt_buffer_decode_2_bytes(pkt_buf, &tcp_hdr->dst_port);
    pkt_buffer_decode_4_bytes(pkt_buf, &tcp_hdr->seq_no);
    pkt_buffer_decode_4_bytes(pkt_buf, &tcp_hdr->ack_no);

    tcp_hdr->hdr_len    = (pkt_buf->buffer[pkt_buf->offset] & 0xF0) >> 4;
    // drop malformed TCP header length
    if ((tcp_hdr->hdr_len * 4) < NETOS_TCP_HDR_LEN_DEFAULT) {
        return NETOS_STATUS_TCP_MALFORMED_PKT;
    }

    tcp_hdr->flags.ecn  = !!(pkt_buf->buffer[pkt_buf->offset] & 0x01);
    pkt_buf->offset ++;

    tcp_hdr->flags.cwr = !!(pkt_buf->buffer[pkt_buf->offset] & 0x80);
    tcp_hdr->flags.ece = !!(pkt_buf->buffer[pkt_buf->offset] & 0x40);
    tcp_hdr->flags.urg = !!(pkt_buf->buffer[pkt_buf->offset] & 0x20);
    tcp_hdr->flags.ack = !!(pkt_buf->buffer[pkt_buf->offset] & 0x10);
    tcp_hdr->flags.psh = !!(pkt_buf->buffer[pkt_buf->offset] & 0x08);
    tcp_hdr->flags.rst = !!(pkt_buf->buffer[pkt_buf->offset] & 0x04);
    tcp_hdr->flags.syn = !!(pkt_buf->buffer[pkt_buf->offset] & 0x02);
    tcp_hdr->flags.fin = !!(pkt_buf->buffer[pkt_buf->offset] & 0x01);

    // validate TCP flags
    ret = netos_tcp_validate_flags(tcp_hdr, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    pkt_buf->offset ++;

    pkt_buffer_decode_2_bytes(pkt_buf, &tcp_hdr->window);

    pkt_buffer_decode_2_bytes(pkt_buf, &tcp_hdr->chksum);
    pkt_buffer_decode_2_bytes(pkt_buf, &tcp_hdr->urg);

    return NETOS_STATUS_SUCCESS;
}

void netos_tcp_print(netos_tcp_hdr_t *tcp_hdr)
{
    netos_log_debug("TCP:\n");
    netos_log_debug("\t src_port: %d\n", tcp_hdr->src_port);
    netos_log_debug("\t dst_port: %d\n", tcp_hdr->dst_port);
    netos_log_debug("\t seq_no: %u\n", tcp_hdr->seq_no);
    netos_log_debug("\t ack_no: %u\n", tcp_hdr->ack_no);
    netos_log_debug("\t hdr_len: %d\n", tcp_hdr->hdr_len);
    netos_log_debug("\t flags:\n");
    netos_log_debug("\t\t ecn: %d\n", tcp_hdr->flags.ecn);
    netos_log_debug("\t\t cwr: %d\n", tcp_hdr->flags.cwr);
    netos_log_debug("\t\t ece: %d\n", tcp_hdr->flags.ece);
    netos_log_debug("\t\t urg: %d\n", tcp_hdr->flags.urg);
    netos_log_debug("\t\t ack: %d\n", tcp_hdr->flags.ack);
    netos_log_debug("\t\t psh: %d\n", tcp_hdr->flags.psh);
    netos_log_debug("\t\t rst: %d\n", tcp_hdr->flags.rst);
    netos_log_debug("\t\t syn: %d\n", tcp_hdr->flags.syn);
    netos_log_debug("\t\t fin: %d\n", tcp_hdr->flags.fin);
}

