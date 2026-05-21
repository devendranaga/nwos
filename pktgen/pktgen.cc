#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <iostream>
#include <memory>
#include <thread>

#include "logging.h"
#include "raw_socket.h"
#include "packet_buf.h"
#include "event_mgr.h"
#include "ethertypes.h"
#include "eth.h"
#include "macsec_hdr.h"
#include "arp_hdr.h"
#include "vlan.h"
#include "avtp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "udp.h"
#include "checksum.h"
#include "protocols.h"
#include "pktgen_config.h"
#include "pktgen.h"

namespace netos {

void pktgen::gen_eth()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    eth_hdr eh;
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;

    for (i = 0; i < config->eth_config.count; i ++) {
        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        memcpy(eh.src_mac, config->eth_config.src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->eth_config.dst_mac, NETOS_MACADDR_LEN);
        eh.ethertype = config->eth_config.ethertype;

        eh.serialize(pktbuf);

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->eth_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
        free(pktbuf);
    }
}

void pktgen::gen_macsec()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i;

    for (i = 0; i < config->macsec_config.count; i ++) {
        uint8_t buf[1024] = {0};

        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        memcpy(eh.src_mac, config->macsec_config.eth_src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->macsec_config.eth_dst_mac, NETOS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_MACSEC;
        eh.serialize(pktbuf);

        macsec_hdr mh;

        mh.tci.ver = config->macsec_config.tci.version;
        mh.tci.es = config->macsec_config.tci.es;
        mh.tci.sc = config->macsec_config.tci.sc;
        mh.tci.scb = config->macsec_config.tci.scb;
        mh.tci.e = config->macsec_config.tci.e;
        mh.tci.c = config->macsec_config.tci.c;
        mh.tci.an = config->macsec_config.tci.an;
        mh.short_len = config->macsec_config.short_len + 2;
        mh.pn = config->macsec_config.pn;
        memcpy(mh.sci.mac, config->macsec_config.sci_mac, NETOS_MACADDR_LEN);
        mh.sci.port_id = config->macsec_config.sci_port_id;
        mh.ethertype = config->macsec_config.macsec_ethertype;
        mh.data = buf;
        mh.data_len = config->macsec_config.short_len;
        memcpy(mh.icv, config->macsec_config.icv, NETOS_MACSEC_ICV_LEN);
        mh.serialize(pktbuf);

        printf("offset %d\n", pktbuf->offset_);
        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->macsec_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
        free(pktbuf);
    }
}

void pktgen::gen_vlan()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;

    for (i = 0; i < config->vlan_config.count; i ++) {
        uint32_t n_vlans = 0;

        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        memcpy(eh.src_mac, config->vlan_config.eth_src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->vlan_config.eth_dst_mac, NETOS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_VLAN;
        eh.serialize(pktbuf);

        for (auto it : config->vlan_config.vlan_ids) {
            vlan_hdr vh;

            n_vlans ++;

            vh.vid = it;
            if (n_vlans == config->vlan_config.vlan_ids.size()) {
                vh.ethertype = config->vlan_config.ethertype;
            } else {
                vh.ethertype = NETOS_ETHERTYPE_VLAN;
            }
            vh.serialize(pktbuf);
        }

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->vlan_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
        free(pktbuf);
    }
}

void pktgen::gen_arp()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;

    for (i = 0; i < config->arp_config.count; i ++) {
        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        memcpy(eh.src_mac, config->arp_config.eth_src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->arp_config.eth_dst_mac, NETOS_MACADDR_LEN);
        if (config->arp_config.vlan_ids.size() > 0) {
            eh.ethertype = NETOS_ETHERTYPE_VLAN;
        } else {
            eh.ethertype = NETOS_ETHERTYPE_ARP;
        }
        eh.serialize(pktbuf);

        // If there is a VLAN setup in the rules, configure them
        if (config->arp_config.vlan_ids.size() > 0) {
            std::vector<uint16_t>::iterator it = config->arp_config.vlan_ids.begin();
            do {
                vlan_hdr vh;

                vh.vid = *it;
                if (it == config->arp_config.vlan_ids.end() - 1) {
                    vh.ethertype = NETOS_ETHERTYPE_ARP;
                } else {
                    vh.ethertype = NETOS_ETHERTYPE_VLAN;
                }
                vh.serialize(pktbuf);
                it ++;
            } while (it != config->arp_config.vlan_ids.end());
        }

        arp_hdr ah;
        ah.hw_type              = config->arp_config.hw_type;
        ah.protocol_type        = config->arp_config.protocol;
        ah.ha_len               = config->arp_config.ha_len;
        ah.proto_len            = config->arp_config.protocol_addr_len;
        ah.op                   = config->arp_config.arp_op;
        memcpy(ah.sender_hwaddr, config->arp_config.sender_hwaddr, NETOS_MACADDR_LEN);
        ah.sender_protocol_addr = config->arp_config.sender_protocol_addr;
        memcpy(ah.target_hwaddr, config->arp_config.target_hwaddr, NETOS_MACADDR_LEN);
        ah.target_protocol_addr = config->arp_config.target_protocol_addr;
        ah.serialize(pktbuf);

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->arp_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
        free(pktbuf);
    }
}

void pktgen::gen_avtp()
{
    packet_buf *pktbuf;
    uint8_t dst_mac[6] = {};

        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        eh.dst_mac[0] = 0xff,
        eh.dst_mac[1] = 0xff,
        eh.dst_mac[2] = 0xff,
        eh.dst_mac[3] = 0xff,
        eh.dst_mac[4] = 0xff,
        eh.dst_mac[5] = 0xff,

        eh.src_mac[0] = 0x02,
        eh.src_mac[1] = 0x02,
        eh.src_mac[2] = 0x02,
        eh.src_mac[3] = 0x02,
        eh.src_mac[4] = 0x02,
        eh.src_mac[5] = 0x02,

        eh.ethertype = NETOS_ETHERTYPE_AVTP;
        eh.serialize(pktbuf);

        avtp_header avtp;

        avtp.subtype = AVTP_SUBTYPE_NTSCF;
        avtp.ntscf_h = (ntscf_header *)calloc(1, sizeof(ntscf_header));
        avtp.ntscf_h->opt.sv = 1;
        avtp.ntscf_h->opt.version = 1;
        avtp.ntscf_h->opt.seq_no = 1;
        avtp.ntscf_h->stream_id[0] = 0x01;
        avtp.ntscf_h->opt.ntscf_data_len = 32;
        avtp.ntscf_h->acf_opt.acf_msg_type = ACF_CAN;
        avtp.ntscf_h->acf_opt.acf_msg_len = 4;
        avtp.ntscf_h->can_hdr = (acf_can_header *)calloc(1, sizeof(acf_can_header));
        avtp.ntscf_h->can_hdr->can_id = 0x600;
        avtp.ntscf_h->can_hdr->can_msg_len = 7;
        avtp.ntscf_h->can_hdr->can_payload[0] = 0x01;
        avtp.ntscf_h->can_hdr->can_payload[1] = 0x01;
        avtp.ntscf_h->can_hdr->can_payload[2] = 0x01;
        avtp.ntscf_h->can_hdr->can_payload[3] = 0x01;
        avtp.ntscf_h->can_hdr->can_payload[4] = 0x01;
        avtp.ntscf_h->can_hdr->can_payload[5] = 0x01;
        avtp.ntscf_h->can_hdr->can_payload[6] = 0x01;
        avtp.serialize(pktbuf);

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);

        pktbuf->free_ptr();
        free(pktbuf);
}

void pktgen::gen_ipv4()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;
    uint8_t *buf = NULL;
    netos_status ret;

    if (config->ipv4_config.total_len != 0) {
        buf = (uint8_t *)calloc(1, config->ipv4_config.total_len);
        if (!buf) {
            return;
        }
    }

    for (i = 0; i < config->ipv4_config.count; i ++) {
        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        ipv4_hdr ipv4_h;

        memcpy(eh.src_mac, config->ipv4_config.eth_src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->ipv4_config.eth_dst_mac, NETOS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_IPV4;
        if (config->ipv4_config.vlan_enable) {
            eh.ethertype = NETOS_ETHERTYPE_VLAN;
        }
        eh.serialize(pktbuf);

        if (config->ipv4_config.vlan_enable) {
            for (auto it : config->ipv4_config.vlan_ids) {
                vlan_hdr vh;

                vh.vid = it;
                vh.ethertype = NETOS_ETHERTYPE_IPV4;
                vh.serialize(pktbuf);
            }
        }

        ipv4_h.version = NETOS_IPV4_VERSION;
        ipv4_h.ihl = NETOS_IPV4_IHL_DEFAULT;
        ipv4_h.dscp = config->ipv4_config.dscp;
        ipv4_h.ecn = config->ipv4_config.ecn;
        ipv4_h.total_len = config->ipv4_config.total_len;
        ipv4_h.id = config->ipv4_config.id;
        ipv4_h.flags.reserved = config->ipv4_config.reserved;
        ipv4_h.flags.df = config->ipv4_config.df;
        ipv4_h.flags.mf = config->ipv4_config.mf;
        ipv4_h.ttl = config->ipv4_config.ttl;
        ipv4_h.protocol = config->ipv4_config.protocol;

        ipv4_h.hdr_chksum = 0;
        if (config->ipv4_config.hdr_checksum_autogen == false)
            ipv4_h.hdr_chksum = config->ipv4_config.hdr_checksum;

        ipv4_h.frag_off = config->ipv4_config.frag_off;
        ipv4_h.src_addr = config->ipv4_config.src_addr;
        ipv4_h.dst_addr = config->ipv4_config.dst_addr;
        ret = ipv4_h.serialize(pktbuf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return;
        }

        pktbuf->serialize_bytes(buf, config->ipv4_config.total_len);

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->ipv4_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
        free(pktbuf);
    }

    if (buf)
        free(buf);
}

void pktgen::gen_ipv6()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;
    uint8_t *buf = NULL;
    netos_status ret;

    if (config->ipv6_config.payload_len != 0) {
        buf = (uint8_t *)calloc(1, config->ipv6_config.payload_len);
        if (!buf) {
            return;
        }
    }

    for (i = 0; i < config->ipv6_config.count; i ++) {
        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        ipv6_hdr ipv6_h;

        memcpy(eh.src_mac, config->ipv6_config.eth_src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->ipv6_config.eth_dst_mac, NETOS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_IPV6;
        eh.serialize(pktbuf);

        ipv6_h.version = NETOS_IPV6_VERSION;
        ipv6_h.traffic_class = config->ipv6_config.traffic_class;
        ipv6_h.flow_label = config->ipv6_config.flow_label;
        ipv6_h.payload_len = config->ipv6_config.payload_len;
        ipv6_h.nh = config->ipv6_config.nh;
        ipv6_h.hop_limit = config->ipv6_config.hop_limit;

        memcpy(ipv6_h.src_addr, config->ipv6_config.src_addr, NETOS_IPV6_ADDR_LEN);
        memcpy(ipv6_h.dst_addr, config->ipv6_config.dst_addr, NETOS_IPV6_ADDR_LEN);
        ipv6_h.options = 0;

        ret = ipv6_h.serialize(pktbuf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return;
        }

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->ipv4_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
        free(pktbuf);
    }
}

void pktgen::gen_icmp()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;
    uint8_t *buf = NULL;
    netos_status ret;

    if (config->icmp_config.payload_len != 0) {
        buf = (uint8_t *)calloc(1, config->icmp_config.payload_len);
        if (!buf) {
            return;
        }
    }

    for (i = 0; i < config->icmp_config.count; i ++) {
        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        ipv4_hdr ipv4_h;

        memcpy(eh.src_mac, config->icmp_config.eth_src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->icmp_config.eth_dst_mac, NETOS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_IPV4;
        eh.serialize(pktbuf);

        ipv4_h.version = NETOS_IPV4_VERSION;
        ipv4_h.ihl = NETOS_IPV4_IHL_DEFAULT;
        ipv4_h.dscp = 0;
        ipv4_h.ecn = 0;
        ipv4_h.total_len = (NETOS_IPV4_IHL_DEFAULT * 4) +
                            NETOS_ICMP_HDR_LEN +
                            NETOS_ICMP_ECHO_REQ_HDR_LEN + config->icmp_config.payload_len;
        ipv4_h.id = 0x1212;
        ipv4_h.flags.reserved = 0;
        ipv4_h.flags.df = 0;
        ipv4_h.flags.mf = 0;
        ipv4_h.ttl = 64;
        ipv4_h.protocol = NETOS_IP_PROTOCOL_ICMP;

        ipv4_h.hdr_chksum = 0;

        ipv4_h.frag_off = 0;
        ipv4_h.src_addr = config->icmp_config.src_addr;
        ipv4_h.dst_addr = config->icmp_config.dst_addr;
        ret = ipv4_h.serialize(pktbuf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return;
        }

        icmp_hdr icmp_h;
        icmp_h.type = config->icmp_config.type;
        icmp_h.code = config->icmp_config.code;

        if (icmp_h.is_echo_req()) {

            icmp_h.echo_request.identifier = config->icmp_config.identifier;
            icmp_h.echo_request.sequence_number = config->icmp_config.sequence_number;

        } else if (icmp_h.is_echo_reply()) {

            icmp_h.echo_reply.identifier = config->icmp_config.identifier;
            icmp_h.echo_reply.sequence_number = config->icmp_config.sequence_number;

        } else {
            goto free_pktbuf;
        }

        ret = icmp_h.serialize(pktbuf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            goto free_pktbuf;
        }

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(
                        std::chrono::nanoseconds(config->icmp_config.pkt_intvl_nsec));

free_pktbuf:
        pktbuf->free_ptr();
        free(pktbuf);
    }

    if (buf)
        free(buf);
}

void pktgen::gen_icmpv6()
{
}

void pktgen::gen_tcp()
{
}

void pktgen::gen_udp()
{
    packet_buf *pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;
    uint8_t *buf = NULL;
    netos_status ret;

    if (config->udp_config.payload_len != 0) {
        buf = (uint8_t *)calloc(1, config->udp_config.payload_len);
        if (!buf) {
            return;
        }
    }

    for (i = 0; i < config->udp_config.count; i ++) {
        pktbuf = (packet_buf *)calloc(1, sizeof(packet_buf));
        if (!pktbuf) {
            return;
        }
        pktbuf->allocate();

        eth_hdr eh;
        ipv4_hdr ipv4_h;

        memcpy(eh.src_mac, config->udp_config.eth_src_mac, NETOS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->udp_config.eth_dst_mac, NETOS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_IPV4;
        eh.serialize(pktbuf);

        ipv4_h.version = NETOS_IPV4_VERSION;
        ipv4_h.ihl = NETOS_IPV4_IHL_DEFAULT;
        ipv4_h.dscp = 0;
        ipv4_h.ecn = 0;
        ipv4_h.total_len = (NETOS_IPV4_IHL_DEFAULT * 4) +
                            NETOS_UDP_HDR_LEN_DEFAULT +
                            config->udp_config.payload_len;
        ipv4_h.id = 0x1212;
        ipv4_h.flags.reserved = 0;
        ipv4_h.flags.df = 0;
        ipv4_h.flags.mf = 0;
        ipv4_h.ttl = 64;
        ipv4_h.protocol = NETOS_IP_PROTOCOL_UDP;

        ipv4_h.hdr_chksum = 0;

        ipv4_h.frag_off = 0;
        ipv4_h.src_addr = config->udp_config.src_addr;
        ipv4_h.dst_addr = config->udp_config.dst_addr;
        ret = ipv4_h.serialize(pktbuf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            return;
        }

        udp_hdr udp_h;
        checksum_pseudo_hdr pseudo_hdr;
        uint32_t src_addr_endian = htonl(config->udp_config.src_addr);
        uint32_t dst_addr_endian = htonl(config->udp_config.dst_addr);
        uint32_t checksum_val;

        udp_h.src_port = config->udp_config.src_port;
        udp_h.dst_port = config->udp_config.dst_port;
        udp_h.len = NETOS_UDP_HDR_LEN_DEFAULT + config->udp_config.payload_len;
        udp_h.checksum = 0;

        ret = udp_h.serialize(pktbuf);
        if (ret != netos_status::NETOS_STATUS_SUCCESS) {
            goto free_pktbuf;
        }

        if (config->udp_config.payload_len > 0) {
            memcpy(&pktbuf->buf_[pktbuf->offset_], buf, config->udp_config.payload_len);
            pktbuf->offset_ += config->udp_config.payload_len;
        }

        pktbuf->len_ = pktbuf->offset_;

        pseudo_hdr.fill_udp(udp_h.start_off,
                            (uint8_t *)&src_addr_endian,
                            (uint8_t *)&dst_addr_endian);
        checksum_val = netos::checksum(pktbuf, &pseudo_hdr);
        pktbuf->buf_[udp_h.checksum_off] = (checksum_val & 0xFF00) >> 8;
        pktbuf->buf_[udp_h.checksum_off + 1] = checksum_val & 0xFF;

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(
                        std::chrono::nanoseconds(config->icmp_config.pkt_intvl_nsec));

free_pktbuf:
        pktbuf->free_ptr();
        free(pktbuf);
    }

    if (buf)
        free(buf);
}

void pktgen::usage(const std::string &progname)
{
    netos_log_info("%s: -f <config file>\n", progname.c_str());
}

void pktgen::run(int argc, char **argv)
{
    std::string config_file;
    pktgen_config *config = pktgen_config::instance();
    int ret;

    while ((ret = getopt(argc, argv, "f:")) != -1) {
        switch (ret) {
            case 'f':
                config_file = optarg;
            break;
            default:
                this->usage(argv[0]);
                return;
        }
    }

    config->parse(config_file);
    config->print();

    raw_fd_ = std::make_shared<netos::lib::raw_socket>(config->interface, 0);
    if (config->eth_config.enable) {
        this->gen_eth();
    }
    if (config->macsec_config.enable) {
        this->gen_macsec();
    }
    if (config->arp_config.enable) {
        this->gen_arp();
    }
    if (config->vlan_config.enable) {
        this->gen_vlan();
    }
    if (config->ipv4_config.enable) {
        this->gen_ipv4();
    }
    if (config->icmp_config.enable) {
        this->gen_icmp();
    }
    if (config->tcp_config.enable) {
        this->gen_tcp();
    }
    if (config->ipv6_config.enable) {
        this->gen_ipv6();
    }
    if (config->udp_config.enable) {
        this->gen_udp();
    }
    //this->gen_avtp();
}

}

int main(int argc, char **argv)
{
    netos::pktgen pgen;

    pgen.run(argc, argv);
}
