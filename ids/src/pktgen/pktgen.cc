#include <stdint.h>
#include <getopt.h>

#include <iostream>
#include <memory>
#include <thread>

#include "logging.h"
#include "raw_socket.h"
#include "packet_buf.h"
#include "eth.h"
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
}

}

}

int main(int argc, char **argv)
{
    netos::ids::pktgen pgen;

    pgen.run(argc, argv);
}
