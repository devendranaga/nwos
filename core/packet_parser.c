#include "pkt_buffer.h"
#include "protocols.h"
#include "arp.h"
#include "ipv4.h"
#include "packet_parser.h"
#include "parser_thread_ctx.h"
#include "ethertypes.h"
#include "netos_log.h"
#include "netos_status.h"
#include "netos_config.h"
#include "checksum.h"
#include "checksum_l4.h"
#include "event_info.h"

netos_status_t netos_parse_l4(pkt_buffer_t *pkt_buf,
                              netos_packet_parser_t *parsed_data)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;
    uint16_t start_off;
    uint16_t remaining_len;

    start_off       = pkt_buf->offset;
    remaining_len   = pkt_buffer_remaining_rx_len(pkt_buf);

    switch (parsed_data->protocol) {
        case NETOS_PROTOCOL_TCP:
            ret = netos_tcp_decode(&parsed_data->l4.tcp_hdr, pkt_buf);
            if (ret == NETOS_STATUS_SUCCESS) {
                ret = netos_do_checksum_l4(start_off,
                                           remaining_len,
                                           parsed_data,
                                           pkt_buf);
                if (ret != NETOS_STATUS_SUCCESS) {
                    NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                               NETOS_EVENT_TYPE_DENY,
                                               NETOS_EVENT_DESC_TCP_CHECKSUM_VERIFY_FAILED);
                    return ret;
                }
            }
        break;
        case NETOS_PROTOCOL_ICMP6:
            ret = netos_icmp6_decode(&parsed_data->l4.icmp6_hdr, pkt_buf);
            if (ret == NETOS_STATUS_SUCCESS) {
                ret = netos_do_checksum_l4(start_off,
                                           remaining_len,
                                           parsed_data,
                                           pkt_buf);
                if (ret != NETOS_STATUS_SUCCESS) {
                    NETOS_PKT_BUFFER_SET_EVENT(pkt_buf,
                                               NETOS_EVENT_TYPE_DENY,
                                               NETOS_EVENT_DESC_ICMP6_CHECKSUM_VERIFY_FAILED);
                    return ret;
                }
            }
        break;
    }

    return ret;
}

netos_status_t netos_parse_frame(pkt_buffer_t *pkt_buf,
                                 netos_packet_parser_t *parsed_data)
{
    netos_status_t ret = NETOS_STATUS_SUCCESS;
    uint16_t ethertype = 0;
    uint32_t i = 0;

    netos_parsed_frame_init(parsed_data);

    parsed_data->has_l2_protocol = false;

    ret = netos_eth_decode(&parsed_data->eh, pkt_buf);
    if (ret != NETOS_STATUS_SUCCESS) {
        return ret;
    }

    ethertype = parsed_data->eh.ethertype;

check_ethertype:
    if (i > NETOS_MAX_VLAN_TUNNELS) {
        return NETOS_STATUS_VLAN_MAX_TUNNELS;
    }

    if ((ethertype == NETOS_ETHERTYPE_VLAN) ||
        (ethertype == NETOS_ETHERTYPE_NON_STD_VLAN) ||
        (ethertype == NETOS_ETHERTYPE_8021AD)) {

        parsed_data->vlan_hdr[i].vlan_ethertype = ethertype;
        ret = netos_vlan_decode(&parsed_data->vlan_hdr[i], pkt_buf);
        if (ret == NETOS_STATUS_SUCCESS) {
            parsed_data->has_l2_protocol = true;
            ethertype = parsed_data->vlan_hdr[i].ethertype;
            i ++;

            goto check_ethertype;
        }
    }

    parsed_data->n_vlans = i;

    if (ethertype == NETOS_ETHERTYPE_MACSEC) {
        ret = netos_macsec_decode(&parsed_data->macsec_hdr, pkt_buf);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }

        if (parsed_data->macsec_hdr.tci_an.e == 0) {
            parsed_data->has_l2_protocol = true;
        }
    }

    parsed_data->ethertype = ethertype;

    if (ethertype == NETOS_ETHERTYPE_ARP) {
        // Decode ARP frame
        ret = netos_arp_decode(&parsed_data->arp_hdr, pkt_buf);
        if (ret == NETOS_STATUS_SUCCESS) {
            netos_arp_mib_in_arp_ok();

            // Process ARP frame
            ret = netos_arp_rx_process(pkt_buf, parsed_data);
            if (ret == NETOS_STATUS_SUCCESS) {
                parsed_data->has_l2_protocol = true;
            }
        } else {
            netos_arp_mib_in_arp_invalid();
            return ret;
        }

    } else if (ethertype == NETOS_ETHERTYPE_IPV4) {
        ret = netos_ipv4_decode(&parsed_data->l3.ipv4_hdr, pkt_buf);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }
        parsed_data->protocol = parsed_data->l3.ipv4_hdr.protocol;

        ret = netos_ipv4_rx_process(pkt_buf, parsed_data);

    } else if (ethertype == NETOS_ETHERTYPE_IPV6) {
        ret = netos_ipv6_decode(&parsed_data->l3.ipv6_hdr, pkt_buf);
        if (ret != NETOS_STATUS_SUCCESS) {
            return ret;
        }
        parsed_data->protocol = parsed_data->l3.ipv6_hdr.nh;
    }

    if (parsed_data->protocol != 0) {
        ret = netos_parse_l4(pkt_buf, parsed_data);
    }

    return ret;
}

