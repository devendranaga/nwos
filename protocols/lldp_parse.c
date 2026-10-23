#include "lldp_hdr.h"
#include "netos_status.h"
#include "common.h"

static netos_status_t netos_lldp_parse_chassis(netos_lldp_hdr_t *lldp_hdr,
                                               uint16_t len,
                                               pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_LLDP_MALFORMED_PKT;

    pkt_buffer_decode_byte(pkt_buf, &lldp_hdr->chassis.chassis_id_subtype);
    if (lldp_hdr->chassis.chassis_id_subtype == NETOS_LLDP_CHASSIS_SUBTYPE_MAC) {
        pkt_buffer_decode_bytes(pkt_buf, lldp_hdr->chassis.mac, NETOS_MACADDR_LEN);
        ret = NETOS_STATUS_SUCCESS;
    }

    return ret;
}

static netos_status_t netos_lldp_parse_port(netos_lldp_hdr_t *lldp_hdr,
                                            uint16_t len,
                                            pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_LLDP_MALFORMED_PKT;

    pkt_buffer_decode_byte(pkt_buf, &lldp_hdr->port.port_id_subtype);
    if (lldp_hdr->port.port_id_subtype == NETOS_LLDP_PORT_SUBTYPE_MAC) {
        pkt_buffer_decode_bytes(pkt_buf, lldp_hdr->port.mac, NETOS_MACADDR_LEN);
        ret = NETOS_STATUS_SUCCESS;
    }

    return ret;
}

static netos_status_t netos_lldp_parse_ttl(netos_lldp_hdr_t *lldp_hdr,
                                           uint16_t len,
                                           pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if (len != 0) {
        pkt_buffer_decode_2_bytes(pkt_buf, &lldp_hdr->ttl_secs);
    }

    return ret;
}

static netos_status_t netos_lldp_parse_system_name(netos_lldp_hdr_t *lldp_hdr,
                                                   uint16_t len,
                                                   pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if (len != 0) {
        lldp_hdr->sys_name.sys_name = &pkt_buf->buffer[pkt_buf->offset];
        lldp_hdr->sys_name.sys_name_len = len;
    }

    return ret;
}

static netos_status_t netos_lldp_parse_system_desc(netos_lldp_hdr_t *lldp_hdr,
                                                   uint16_t len,
                                                   pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;

    if (len != 0) {
        lldp_hdr->sys_desc.sys_desc = &pkt_buf->buffer[pkt_buf->offset];
        lldp_hdr->sys_desc.sys_desc_len = len;
    }

    return ret;
}


const struct {
    netos_lldp_type_t type;
    netos_status_t (*callback)(netos_lldp_hdr_t *lldp_hdr,
                               uint16_t len,
                               pkt_buffer_t *pkt_buf);
} netos_lldp_callbacks[] = {
    {
        NETOS_LLDP_TYPE_CHASSIS_ID,
        netos_lldp_parse_chassis,
    },
    {
        NETOS_LLDP_TYPE_PORT_ID,
        netos_lldp_parse_port,
    },
    {
        NETOS_LLDP_TYPE_TTL,
        netos_lldp_parse_ttl,
    },
    {
        NETOS_LLDP_TYPE_SYSNAME,
        netos_lldp_parse_system_name,
    },
    {
        NETOS_LLDP_TYPE_SYSDESC,
        netos_lldp_parse_system_desc
    }
};

netos_status_t netos_lldp_decode(netos_lldp_hdr_t *lldp_hdr, pkt_buffer_t *pkt_buf)
{
    netos_status_t ret = NETOS_STATUS_LLDP_MALFORMED_PKT;

    if (pkt_buffer_remaining_rx_len(pkt_buf) < NETOS_LLDP_MIN_HDR_LEN) {
        return NETOS_STATUS_LLDP_MALFORMED_PKT;
    }

    do {
        uint16_t data;
        uint16_t type;
        uint16_t len;
        uint32_t i;

        pkt_buffer_decode_2_bytes(pkt_buf, &data);

        type = (data & 0xFE00) >> 9;
        len = (data & 0x01FF);

        // the end of lldp tag matched
        if ((type == NETOS_LLDP_TYPE_END) && (len == 0)) {
            break;
        }

        for (i = 0; i < NETOS_SIZEOF_ARRAY(netos_lldp_callbacks); i ++) {
            if (netos_lldp_callbacks[i].type == type) {
                ret = netos_lldp_callbacks[i].callback(lldp_hdr, len, pkt_buf);
                if (ret != NETOS_STATUS_SUCCESS) {
                    return ret;
                }
            }
        }

    } while (pkt_buffer_remaining_rx_len(pkt_buf) > 0);

    return ret;
}
