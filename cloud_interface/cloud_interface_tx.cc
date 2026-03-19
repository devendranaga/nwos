#include <iostream>
#include <cstdint>
#include <atomic>

#include "network_config.h"
#include "cloud_interface.h"
#include "cloud_interface_tx.h"

namespace netos {

netos_status cloud_interface_tx::initialize()
{
    network_config *config = network_config::instance();
    gcd *gcd_instance = gcd::instance();

    this->client_sock_ = std::make_shared<udp_client_socket>();

    this->server_addr_.sin_family = AF_INET;
    this->server_addr_.sin_port = htons(config->cloud_config_.server_port);
    this->server_addr_.sin_addr.s_addr = inet_addr(config->cloud_config_.server_ip.c_str());

    std::function<void(void)> stats_timer_callback = std::bind(&cloud_interface_tx::netos_cloud_intf_stats_send_timer,
                                                               this);

    // create transmit timer for statistics
    gcd_instance->register_timer(config->cloud_config_.stats_tx_interval_sec,
                                 0, stats_timer_callback);

    return netos_status::NETOS_STATUS_SUCCESS;
}

void cloud_interface_tx::netos_cloud_intf_stats_send_timer()
{
        printf("cloud inerface timer\n");
}

}

