#include <stdint.h>
#include <stdio.h>
#include <getopt.h>

#include "logging.h"
#include "pool.h"
#include "network_main.h"

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

    }
}

void network_interface::rx_thread()
{
    uint8_t buf[2048];
    int ret;

    netos_log_info("create rx thread ok\n");

    while (1) {
        ret = this->raw_->recv_msg(buf, sizeof(buf));
        netos_log_info("ret %d\n", ret);
    }
}

netos_status network_interface::initialize(network_if_config &if_config)
{
    netos_log_info("initialize interface <%s>\n", if_config.ifname.c_str());

    this->raw_ = std::make_shared<raw_socket>(if_config.ifname, 0);

    netos_log_info("created raw socket on <%s>\n", if_config.ifname.c_str());

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

