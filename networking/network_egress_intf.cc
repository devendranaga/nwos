#include "ids_macro_defs.h"
#include "network_egress_intf.h"

namespace netos {

void network_egress::egress_tx_thread()
{
    uint8_t dst[NETOS_MACADDR_LEN] = {0};

    while (1) {
        std::unique_lock<std::mutex> l(this->egress_queue_lock_);
        this->egress_queue_cond_.wait(l);

        printf("received egress frame\n");
        while (!this->egress_queue_.empty()) {
            std::shared_ptr<network_egress_intf> intf = this->egress_queue_.front();
            this->egress_queue_.pop();

            printf("send egress frame %s %d\n", intf->ifname.c_str(), intf->pkt->offset_);
            intf->raw_fd_->send_msg(dst, intf->pkt->buf_, intf->pkt->offset_);
        }
    }
}

void network_egress::initialize()
{
    this->egress_thr_ = std::make_shared<std::thread>(&network_egress::egress_tx_thread, this);
    this->egress_thr_->detach();
}

void network_egress::egress_enque(std::shared_ptr<network_egress_intf> intf)
{
    std::unique_lock<std::mutex> l(this->egress_queue_lock_);
    this->egress_queue_.push(intf);
    this->egress_queue_cond_.notify_one();
}

}
