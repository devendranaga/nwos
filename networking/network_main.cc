#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <chrono>

#include "gcd.h"
#include "ethertypes.h"
#include "logging.h"
#include "arp.h"
#include "network_main.h"
#include "statistics.h"

namespace netos {

static void usage(const char *progname)
{
    fprintf(stderr, "usage: %s <-f configuration file>\n", progname);
}

int network_manager::parse_cmdargs(int argc, char **argv)
{
    int ret;

    if (argc == 1) {
        usage(argv[0]);
        return -1;
    }

    while ((ret = getopt(argc, argv, "f:")) != -1) {
        switch (ret) {
            case 'f':
                this->cmdargs_.config_file = std::string(optarg);
            break;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    return 0;
}

void network_manager::run(int argc, char **argv)
{
    network_config *conf;
    gcd *gcd_instance;
    netos_status res;
    int ret;

    gcd_instance = gcd::instance();

    // parse command line arguments
    ret = this->parse_cmdargs(argc, argv);
    if (ret != 0) {
        return;
    }

    // parse configuration file
    conf = network_config::instance();
    res = conf->parse(this->cmdargs_.config_file);
    if (res != netos_status::NETOS_STATUS_SUCCESS) {
        return;
    }

    // initialize logging
    netos_log_init(
            conf->log_config_.debug_log_server_ip.c_str(),
            conf->log_config_.debug_log_server_port);

    arp_context::instance()->init();

    // initialize network interface
    conf = network_config::instance();

    // initialize packet buffer pool
    packet_buf_pool::instance()->initialize(1000);

    // initialize parsed packet buffer pool
    parsed_pkt_pool::instance()->initialize(1000);

    // initialize the event manager
    event_mgr::instance()->initialize();

    for (auto ifname : conf->if_config_.ifname) {
        network_egress *egress;
        std::shared_ptr<network_interface> netif;

        netif = std::make_shared<network_interface>();
        res = netif->initialize(ifname);
        if (res != netos_status::NETOS_STATUS_SUCCESS) {
            netos_log_error("failed to initialize interface <%s>\n", ifname.c_str());
            continue;
        }

        egress = network_egress::instance();
        egress->add_interface_ctx(netif->get_raw_fd(), ifname);

        this->iflist_.push_back(netif);
    }

    while (1) {
        gcd_instance->run();
    }
}

void network_interface::rx_thread()
{
    int ret;

    netos_log_info("create rx thread for <%s> ok\n", this->ifname_.c_str());

    while (1) {
        parsed_pkt *pkt;

        // get an instance of the parsed packet buffer pool
        pkt = parsed_pkt_pool::instance()->get_pkt();
        if (!pkt) {
            return;
        }

        pkt->ifname = this->ifname_;
        pkt->raw = this->raw_;

        // receive the packet from the raw socket
        ret = this->raw_->recv_msg(pkt->pkt_buf->buf_, NETOS_PACKET_BUF_SIZE);
        auto start = std::chrono::steady_clock::now();
        if (ret > 0) {
            pkt->pkt_buf->len_ = ret;
            statistics::instance()->inc_rx_count(this->ifname_);

            // queue the frame to the receive pool
            std::unique_lock<std::mutex> l(this->rx_pkt_pool_lock_);
            this->rx_pkt_pool_.push(pkt);
            rx_pkt_pool_cond_.notify_one();
        }
        auto end = std::chrono::steady_clock::now();
        std::cout << "elapsed " <<
                     std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() <<
                     " microseconds" << std::endl;
        statistics::instance()->print();
    }
}

void network_interface::dispatch_pkt(parsed_pkt *pkt)
{
    if (pkt->pkt_types_present.has_arp) {
        arp_context::instance()->add_rx_frame(pkt);
    }
}

void network_interface::parse_thread()
{
    netos_status ret;

    while (1) {
        std::unique_lock<std::mutex> l(this->rx_pkt_pool_lock_);
        bool free_frame = false;

        rx_pkt_pool_cond_.wait(l);

        // dequeue all the packets from the pool
        while (!this->rx_pkt_pool_.empty()) {
            parsed_pkt *pkt = this->rx_pkt_pool_.front();
            this->rx_pkt_pool_.pop();

            // parse and dispatch them to the corresponding protocol layer
            ret = pkt->parse_frame();
            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->dispatch_pkt(pkt);
            } else {
                statistics::instance()->inc_n_deny_rx(this->ifname_);
                free_frame = true;
            }

            if (this->pcap_) {
                this->pcap_->add_packet(pkt->pkt_buf);
            }

            if (free_frame) {
                parsed_pkt_pool::instance()->put_pkt(pkt);
            }
        }
    }
}

netos_status network_interface::initialize(const std::string &ifname)
{
    network_config *conf = network_config::instance();

    netos_log_info("initialize interface <%s>\n", ifname.c_str());

    this->raw_ = std::make_shared<raw_socket>(ifname, 0);

    netos_log_info("created raw socket on <%s>\n", ifname.c_str());

    this->ifname_ = ifname;

    statistics::instance()->initialize(ifname);

    if (conf->log_config_.log_pcap) {
        this->pcap_ = std::make_shared<pcap_mod>();
        this->pcap_->initialize(ifname, conf->log_config_.pcap_file_path);
    }

    netos_log_info("initialize pcap log for the interface <%s>\n", ifname.c_str());

    // create parser thread
    this->parse_thr_ = std::make_shared<std::thread>(
                                        &network_interface::parse_thread,
                                        this);
    this->parse_thr_->detach();

    // create rx thread
    this->rx_thr_ = std::make_shared<std::thread>(
                                        &network_interface::rx_thread,
                                        this);
    this->rx_thr_->detach();

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

int main(int argc, char **argv)
{
    netos::network_manager netmgr;

    netmgr.run(argc, argv);
}

