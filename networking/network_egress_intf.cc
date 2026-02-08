#include "ids_macro_defs.h"
#include "network_egress_intf.h"
#include "statistics.h"

namespace netos {

void network_egress_interface_ctx::egress_tx_thread()
{
    uint8_t dst[NETOS_MACADDR_LEN] = {0};

    while (1) {
        std::unique_lock<std::mutex> l(this->egress_queue_lock_);
        this->egress_queue_cond_.wait(l);

        netos_log_info("received egress frame for <%s>\n", this->ifname_.c_str());
        while (!this->egress_queue_.empty()) {
            network_egress_intf intf = this->egress_queue_.front();
            this->egress_queue_.pop();

            netos_log_info("send egress frame %s %d\n", intf.ifname.c_str(), intf.pkt->offset_);
            intf.raw_fd_->send_msg(dst, intf.pkt->buf_, intf.pkt->offset_);

            // increment the tx count after tx
            statistics::instance()->inc_tx_count(intf.ifname);
        }
    }
}

void network_egress_interface_ctx::initialize()
{
    this->egress_thr_ = std::make_shared<std::thread>(
                                        &network_egress_interface_ctx::egress_tx_thread,
                                        this);
    this->egress_thr_->detach();
}

void network_egress::add_interface_ctx(std::shared_ptr<raw_socket> raw,
                                       std::string ifname)
{
    std::shared_ptr<network_egress_interface_ctx> ctx;

    ctx = std::make_shared<network_egress_interface_ctx>();
    ctx->raw_fd_ = raw;
    ctx->ifname_ = ifname;
    ctx->initialize();
    this->interface_ctx_list_.push_back(ctx);
}

void network_egress::egress_enque(network_egress_intf &intf)
{
    for (auto it : this->interface_ctx_list_) {
        netos_log_info("trying enqueue <%s> <%s>\n", it->ifname_.c_str(), intf.ifname.c_str());
        if (it->ifname_ == intf.ifname) {
            std::unique_lock<std::mutex> l(it->egress_queue_lock_);
            it->egress_queue_.push(intf);
            it->egress_queue_cond_.notify_one();
            break;
        }
    }
}

}
