#include <pcap.h>

namespace netos {

netos_status pcap_mod::initialize(const std::string &ifname,
                                  const std::string &pcap_filename)
{
    char filename[128];
    time_t now;
    struct tm *t;

    now = time(0);
    t = gmtime(&now);

    snprintf(filename, sizeof(filename),
                    "%s_%s_%04d_%02d_%02d_%02d_%02d_%02d.pcap",
                    pcap_filename.c_str(), ifname.c_str(),
                    t->tm_year + 1900, t->tm_mon + 1,
                    t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    this->pcap_wr_ = std::make_shared<pcap_writer>(filename);
    this->pcap_thr_ = std::make_shared<std::thread>(&pcap_mod::pcap_thread, this);
    this->pcap_thr_->detach();

    return netos_status::NETOS_STATUS_SUCCESS;
}

void pcap_mod::pcap_thread()
{
    while (1) {
        std::unique_lock<std::mutex> lock(this->pkt_queue_lock_);
        this->pkt_queue_cond_.wait(lock);
        while (!this->pkt_queue_.empty()) {
            std::shared_ptr<packet_buf> pkt = this->pkt_queue_.front();
            this->pkt_queue_.pop();

            pcaprec_hdr_t rec = this->pcap_wr_->format_pcap_pkthdr(pkt->get_raw_buf_len());
            this->pcap_wr_->write_packet(&rec, pkt->get_raw_buf());
        }
    }
}

void pcap_mod::add_packet(std::shared_ptr<packet_buf> &pkt)
{
    std::lock_guard<std::mutex> lock(this->pkt_queue_lock_);
    this->pkt_queue_.push(pkt);
    this->pkt_queue_cond_.notify_one();
}

}
