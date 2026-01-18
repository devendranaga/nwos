#include <stdint.h>
#include <stdio.h>
#include <getopt.h>

#include "ethertypes.h"
#include "logging.h"
#include "pool.h"
#include "arp.h"
#include "network_main.h"
#include "statistics.h"

namespace netos {

int network_manager::parse_cmdargs(int argc, char **argv)
{
    int ret;

    while ((ret = getopt(argc, argv, "f:")) != -1) {
        switch (ret) {
            case 'f':
                this->cmdargs_.config_file = std::string(optarg);
            break;
            default:
                return -1;
        }
    }

    return 0;
}

void network_manager::run(int argc, char **argv)
{
    network_config *conf;
    netos_status res;
    int ret;

    ret = this->parse_cmdargs(argc, argv);
    if (ret != 0) {
        return;
    }

    res = network_config::instance()->parse(this->cmdargs_.config_file);
    if (res != netos_status::NETOS_STATUS_SUCCESS) {
        return;
    }

    arp_context::instance()->init();

    conf = network_config::instance();

    for (auto if_config : conf->if_config_list_) {
        std::shared_ptr<network_interface> netif;

        netif = std::make_shared<network_interface>();
        netif->initialize(if_config);
        this->iflist_.push_back(netif);
    }

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void network_interface::tx_thread()
{
    netos_log_info("create tx thread ok\n");

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void network_interface::rx_thread()
{
    netos_status res;
    int ret;

    netos_log_info("create rx thread ok\n");

    while (1) {
        std::shared_ptr<parsed_pkt> pkt;

        pkt = std::make_shared<parsed_pkt>();
        pkt->pkt_buf = std::make_shared<packet_buf>();
        res = pkt->pkt_buf->allocate();
        if (res != netos_status::NETOS_STATUS_SUCCESS) {
            continue;
        }

        pkt->ifname = this->ifname_;

        ret = this->raw_->recv_msg(pkt->pkt_buf->buf_, NETOS_PACKET_BUF_SIZE);
        if (ret > 0) {
            statistics::instance()->inc_rx_count(this->ifname_);
            std::unique_lock<std::mutex> l(this->rx_pkt_pool_lock_);
            this->rx_pkt_pool_.push(pkt);
            rx_pkt_pool_cond_.notify_one();
        }
        statistics::instance()->print();
    }
}

void network_interface::dispatch_pkt(std::shared_ptr<parsed_pkt> pkt)
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
        rx_pkt_pool_cond_.wait(l);
        std::shared_ptr<parsed_pkt> pkt = this->rx_pkt_pool_.front();
        this->rx_pkt_pool_.pop();

        ret = pkt->parse_frame();
        if (ret == netos_status::NETOS_STATUS_SUCCESS) {
            this->dispatch_pkt(pkt);
        }
    }
}

netos_status network_interface::initialize(network_if_config &if_config)
{
    netos_log_info("initialize interface <%s>\n", if_config.ifname.c_str());

    this->raw_ = std::make_shared<raw_socket>(if_config.ifname, 0);

    netos_log_info("created raw socket on <%s>\n", if_config.ifname.c_str());

    this->ifname_ = if_config.ifname;
    this->parse_thr_ = std::make_shared<std::thread>(&network_interface::parse_thread, this);
    this->tx_thr_ = std::make_shared<std::thread>(&network_interface::tx_thread, this);
    this->rx_thr_ = std::make_shared<std::thread>(&network_interface::rx_thread, this);

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

int main(int argc, char **argv)
{
    netos::network_manager netmgr;

    netmgr.run(argc, argv);
}

