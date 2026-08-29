#include <stdint.h>
#include "netos_status.h"
#include "ethertypes.h"
#include "pkt_buffer.h"
#include "checksum.h"
#include "checksum_l4.h"

netos_status_t netos_do_checksum_l4(uint16_t start_off,
                                    uint16_t remaining_len,
                                    netos_packet_parser_t *parsed_data,
                                    pkt_buffer_t *pkt_buf)
{
    netos_checksum_t chksum = {
        .buffer         = &pkt_buf->buffer[start_off],
        .len            = remaining_len,
        .is_v4          = true,
        .u.v4.src_ip    = parsed_data->l3.ipv4_hdr.src_ipaddr,
        .u.v4.dst_ip    = parsed_data->l3.ipv4_hdr.dst_ipaddr,
        .protocol       = parsed_data->protocol
    };

    if (NETOS_IS_IPV6_FRAME(parsed_data)) {
        chksum.is_v4        = false;
        chksum.u.v6.src_ip  = parsed_data->l3.ipv6_hdr.src_ipaddr;
        chksum.u.v6.dst_ip  = parsed_data->l3.ipv6_hdr.dst_ipaddr;
    }

    uint16_t checksum = netos_l4_checksum(&chksum);
    if (checksum == 0) {
        return NETOS_STATUS_SUCCESS;
    }

    return NETOS_STATUS_L4_CHECKSUM_FAILED;
}

