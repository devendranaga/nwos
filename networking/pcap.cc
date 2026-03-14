#include "signal_intf.h"
#include "pcap.h"

namespace netos {

netos_status pcap_mod::make_filename(const std::string &pcap_filename,
                                     const std::string &ifname,
                                     std::string &filename_str)
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

    filename_str = std::string(filename);
    return netos_status::NETOS_STATUS_SUCCESS;
}

netos_status pcap_mod::initialize(const std::string &ifname,
                                  const std::string &pcap_filename)
{
    std::string filename_str;
    netos_status ret;

    ret = this->make_filename(pcap_filename, ifname, filename_str);
    if (ret != netos_status::NETOS_STATUS_SUCCESS) {
        return ret;
    }

    this->pcap_wr_ = std::make_shared<pcap_writer>();
    if (this->pcap_wr_->create_file(filename_str, 1024 * 1024) != 0) {
        return netos_status::NETOS_STATUS_ALLOC_FAILURE;
    }

    this->pcap_thr_ = std::make_shared<std::thread>(&pcap_mod::pcap_thread, this);
    this->pcap_thr_->detach();

    return netos_status::NETOS_STATUS_SUCCESS;
}

void pcap_mod::pcap_thread()
{
    netos_block_term_signals();

    while (1) {
        std::unique_lock<std::mutex> lock(this->pkt_queue_lock_);
        this->pkt_queue_cond_.wait(lock);

        if (this->terminate_) {
            this->pcap_wr_->close_file();
            break;
        }

        while (!this->pkt_queue_.empty()) {
            parsed_pkt *pkt = this->pkt_queue_.front();
            this->pkt_queue_.pop();

            // this should never happen, but if it is then we may have some buffer management issues
            if (pkt->pkt_buf->get_raw_buf_rx_len() == 0) {
                pkt->dec_ref_count();
                parsed_pkt_pool::instance()->put_pkt(pkt);
                continue;
            }

            pcaprec_hdr_t rec = this->pcap_wr_->format_pcap_pkthdr(pkt->pkt_buf->get_raw_buf_rx_len());
            this->pcap_wr_->write_packet(&rec, pkt->pkt_buf->get_raw_buf());
            pkt->dec_ref_count();

            parsed_pkt_pool::instance()->put_pkt(pkt);
        }
    }
}

void pcap_mod::add_packet(parsed_pkt *pkt)
{
    std::lock_guard<std::mutex> lock(this->pkt_queue_lock_);
    pkt->inc_ref_count();
    this->pkt_queue_.push(pkt);
    this->pkt_queue_cond_.notify_one();
}

}

