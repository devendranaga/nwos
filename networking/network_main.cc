#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <chrono>

#include "signal_intf.h"
#include "ioctl_nw.h"
#include "gcd.h"
#include "ethertypes.h"
#include "logging.h"
#include "arp.h"
#include "vlan_membership.h"
#include "cpu_setting.h"
#include "network_main.h"
#include "statistics.h"

namespace netos {

static void usage(const char *progname)
{
    fprintf(stderr, "usage: %s <-f configuration file>\n", progname);
}

/**
 * @brief - Parse command line arguments.
 */
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

void network_manager::termination_handler()
{
    gcd *gcd_instance;

    gcd_instance = gcd::instance();

    netos_log_info("termination signal received\n");

    for (auto it : this->iflist_) {
        it->raise_signals();
    }

    gcd_instance->terminate();
}

void network_interface_config::initialize(const std::string &ifname)
{
    this->ifname = ifname;

    netos_get_macaddr(ifname.c_str(), this->mac);
    netos_get_ipaddr(ifname.c_str(), &this->ipaddr);
}

void network_manager::run(int argc, char **argv)
{
    network_config *conf;
    gcd *gcd_instance;
    netos_status res;
    int ret;

    auto start = std::chrono::steady_clock::now();

    gcd_instance = gcd::instance();

    // initialize 4 threads for the pool
    gcd_instance->initialize_thr_pool(8);

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

    // initialize network interface
    conf = network_config::instance();

    // initialize packet buffer pool
    packet_buf_pool::instance()->initialize(conf->packet_buf_pool_len);

    // initialize parsed packet buffer pool
    parsed_pkt_pool::instance()->initialize(conf->parsed_pkt_buf_pool_len);

    // initialize ARP context
    arp_context::instance()->init();

    // initialize VLAN membership context
    vlan_membership::instance()->initialize();

    // initialize the event manager
    event_mgr::instance()->initialize();

    this->cloud_tx_ = std::make_shared<cloud_interface_tx>();
    this->cloud_tx_->initialize();

    for (auto ifname : conf->if_config_.ifname) {
        network_egress *egress;
        std::shared_ptr<network_interface> netif;

        netif = std::make_shared<network_interface>();

        res = netif->initialize(ifname);
        if (res != netos_status::NETOS_STATUS_SUCCESS) {
            netos_log_error("failed to initialize egress instance for interface <%s>\n", ifname.c_str());
            continue;
        }

        egress = network_egress::instance();
        egress->add_interface_ctx(netif->get_raw_fd(), ifname);

        this->iflist_.push_back(netif);
    }

    term_callback term_cb = std::bind(&network_manager::termination_handler, this);
    gcd_instance->register_term_signal(term_cb);

    auto end = std::chrono::steady_clock::now();
    auto delta_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    netos_log_info("Finished initialization in %d milliseconds\n", delta_ms);

    gcd_instance->run();
}

void network_interface::rx_thread()
{
    int ret;

    netos_block_term_signals();

    netos_log_info("create rx thread for <%s> ok\n", this->intf_config_->ifname.c_str());

    while (1) {
        parsed_pkt *pkt;

        if (this->rx_thread_signalled_) {
            break;
        }

        // get an instance of the parsed packet buffer pool
        pkt = parsed_pkt_pool::instance()->get_pkt();
        if (!pkt) {
            return;
        }

        pkt->intf_config = this->intf_config_;
        pkt->stats = this->stats_;
        pkt->raw = this->raw_;

        // receive the packet from the raw socket
        ret = this->raw_->recv_msg(pkt->pkt_buf->buf_, NETOS_PACKET_BUF_SIZE);
        auto start = std::chrono::steady_clock::now();
        if (ret > 0) {
            pkt->pkt_buf->len_ = ret;
            this->stats_->inc_rx_count();

            // queue the frame to the receive pool
            std::unique_lock<std::mutex> l(this->rx_pkt_pool_lock_);

            // inc refcount before pushing to the pool
            pkt->inc_ref_count();
            this->rx_pkt_pool_.push(pkt);
            rx_pkt_pool_cond_.notify_one();
        }
        auto end = std::chrono::steady_clock::now();
        this->stats_->set_rx_queue_time_ns(
                            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
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

    netos_block_term_signals();

    while (1) {
        std::unique_lock<std::mutex> l(this->rx_pkt_pool_lock_);
        bool free_frame = false;

        rx_pkt_pool_cond_.wait(l);

        if (this->parsed_thread_signalled_) {
            break;
        }

        // dequeue all the packets from the pool
        while (!this->rx_pkt_pool_.empty()) {
#if defined(NETOS_PERF_TIME)
            auto start = std::chrono::steady_clock::now();
#endif

            parsed_pkt *pkt = this->rx_pkt_pool_.front();
            this->rx_pkt_pool_.pop();


            // parse and dispatch them to the corresponding protocol layer
            ret = pkt->parse_frame();
            pkt->dec_ref_count();

            if (ret == netos_status::NETOS_STATUS_SUCCESS) {
                this->dispatch_pkt(pkt);
            } else {
                this->stats_->inc_n_deny_rx();
                free_frame = true;
            }

            if (this->pcap_) {
                this->pcap_->add_packet(pkt);
            }

            if (free_frame) {
                parsed_pkt_pool::instance()->put_pkt(pkt);
            }

#if defined(NETOS_PERF_TIME)
            auto end = std::chrono::steady_clock::now();
            this->stats_->set_parse_time_ns(
                            std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
#endif
        }
    }
}

netos_status network_interface::initialize(const std::string &ifname)
{
    network_config *conf = network_config::instance();

    netos_log_info("initialize interface <%s>\n", ifname.c_str());

    this->raw_ = std::make_shared<raw_socket>(ifname, 0);

    netos_log_info("created raw socket on <%s>\n", ifname.c_str());

    this->intf_config_ = std::make_shared<network_interface_config>();
    this->intf_config_->initialize(ifname);

    this->stats_ = statistics::instance()->initialize(ifname);

    if (conf->log_config_.log_pcap) {
        this->pcap_ = std::make_shared<pcap_mod>();
        this->pcap_->initialize(ifname, conf->log_config_.pcap_file_path);

        netos_log_info("initialize pcap log for the interface <%s>\n", ifname.c_str());
    }

    this->parsed_thread_signalled_ = false;
    this->rx_thread_signalled_ = false;

    // create parser thread
    this->parse_thr_ = std::make_shared<std::thread>(
                                        &network_interface::parse_thread,
                                        this);

    // tie the parser threads to the second core
    netos_set_cpu_affinity(this->parse_thr_->native_handle(), 1);

    this->parse_thr_->detach();

    // create rx thread
    this->rx_thr_ = std::make_shared<std::thread>(
                                        &network_interface::rx_thread,
                                        this);

    // tie the receive threads to the first core
    netos_set_cpu_affinity(this->rx_thr_->native_handle(), 0);

    this->rx_thr_->detach();

    return netos_status::NETOS_STATUS_SUCCESS;
}

}

int main(int argc, char **argv)
{
    netos::network_manager netmgr;

    netmgr.run(argc, argv);

    return 0;
}

