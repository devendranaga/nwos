#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include <iostream>
#include <memory>
#include <thread>

#include "logging.h"
#include "raw_socket.h"
#include "packet_buf.h"
#include "ethertypes.h"
#include "eth.h"
#include "arp_hdr.h"
#include "vlan.h"
#include "ipv4.h"
#include "pktgen_config.h"
#include "pktgen.h"

namespace netos {

namespace ids {

class pktgen {
    public:
        explicit pktgen() = default;
        ~pktgen() = default;

        void run(int argc, char **argv);

    private:
        void usage(const std::string &progname);
        void gen_eth();
        void gen_vlan();
        void gen_arp();
        void gen_ipv4();
        std::shared_ptr<netos::lib::raw_socket> raw_fd_;
};

void pktgen::gen_eth()
{
    std::shared_ptr<packet_buf> pktbuf;
    pktgen_config *config = pktgen_config::instance();
    eth_hdr eh;
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;

    for (i = 0; i < config->eth_config.count; i ++) {
        pktbuf = std::make_shared<packet_buf>();
        pktbuf->allocate();

        memcpy(eh.src_mac, config->eth_config.src_mac, NETOS_IDS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->eth_config.dst_mac, NETOS_IDS_MACADDR_LEN);
        eh.ethertype = config->eth_config.ethertype;

        eh.serialize(pktbuf);

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->eth_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
    }
}

void pktgen::gen_vlan()
{
    std::shared_ptr<packet_buf> pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;

    for (i = 0; i < config->vlan_config.count; i ++) {
        pktbuf = std::make_shared<packet_buf>();
        pktbuf->allocate();

        eth_hdr eh;
        memcpy(eh.src_mac, config->eth_config.src_mac, NETOS_IDS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->eth_config.dst_mac, NETOS_IDS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_VLAN;
        eh.serialize(pktbuf);

        for (auto it : config->vlan_config.vlan_ids) {
            vlan_hdr vh;

            vh.vid = it;
            vh.ethertype = config->vlan_config.ethertype;
            vh.serialize(pktbuf);
        }

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->vlan_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
    }
}

void pktgen::gen_arp()
{
    std::shared_ptr<packet_buf> pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;

    for (i = 0; i < config->arp_config.count; i ++) {
        pktbuf = std::make_shared<packet_buf>();
        pktbuf->allocate();

        eth_hdr eh;
        memcpy(eh.src_mac, config->arp_config.eth_src_mac, NETOS_IDS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->arp_config.eth_dst_mac, NETOS_IDS_MACADDR_LEN);
        eh.ethertype = NETOS_ETHERTYPE_ARP;
        eh.serialize(pktbuf);

        arp_hdr ah;
        ah.hw_type = config->arp_config.hw_type;
        ah.protocol_type = config->arp_config.protocol;
        ah.ha_len = config->arp_config.ha_len;
        ah.proto_len = config->arp_config.protocol_addr_len;
        ah.op = config->arp_config.arp_op;
        memcpy(ah.sender_hwaddr, config->arp_config.sender_hwaddr, NETOS_IDS_MACADDR_LEN);
        ah.sender_protocol_addr = config->arp_config.sender_protocol_addr;
        memcpy(ah.target_hwaddr, config->arp_config.target_hwaddr, NETOS_IDS_MACADDR_LEN);
        ah.target_protocol_addr = config->arp_config.target_protocol_addr;
        ah.serialize(pktbuf);

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->arp_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
    }
}

void pktgen::gen_ipv4()
{
    std::shared_ptr<packet_buf> pktbuf;
    pktgen_config *config = pktgen_config::instance();
    uint8_t dst_mac[6] = {};
    uint32_t i = 0;
    uint8_t *buf = NULL;

    if (config->ipv4_config.total_len != 0) {
        buf = (uint8_t *)calloc(1, config->ipv4_config.total_len);
        if (!buf) {
            return;
        }
    }

    for (i = 0; i < config->ipv4_config.count; i ++) {
        pktbuf = std::make_shared<packet_buf>();
        pktbuf->allocate();

        eth_hdr eh;
        ipv4_hdr ipv4_h;
        uint16_t chksum;

        memcpy(eh.src_mac, config->ipv4_config.eth_src_mac, NETOS_IDS_MACADDR_LEN);
        memcpy(eh.dst_mac, config->ipv4_config.eth_dst_mac, NETOS_IDS_MACADDR_LEN);
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
        ipv4_h.serialize(pktbuf);
        chksum = ipv4_h.checksum(pktbuf);
        pktbuf->buf_[ipv4_h.checksum_off] = (chksum & 0x00FF);
        pktbuf->buf_[ipv4_h.checksum_off + 1] = (chksum & 0xFF00) >> 8;
        pktbuf->serialize_bytes(buf, config->ipv4_config.total_len);

        this->raw_fd_->send_msg(dst_mac, pktbuf->buf_, pktbuf->offset_);
        std::this_thread::sleep_for(std::chrono::nanoseconds(config->ipv4_config.pkt_intvl_nsec));

        pktbuf->free_ptr();
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
    if (config->arp_config.enable) {
        this->gen_arp();
    }
    if (config->vlan_config.enable) {
        this->gen_vlan();
    }
    if (config->ipv4_config.enable) {
        this->gen_ipv4();
    }
}

}

}

int main(int argc, char **argv)
{
    netos::ids::pktgen pgen;

    pgen.run(argc, argv);
}
