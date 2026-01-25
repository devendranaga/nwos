#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fstream>
#include <functional>
#include <system_error>
#include <jsoncpp/json/json.h>

#include "logger.h"

namespace netos {

namespace logging {

void usage(const char *progname)
{
    fprintf(stderr, "%s -i <ipaddr> -p <port>\n", progname);
}

int logger_config::parse(const std::string &config_file)
{
    Json::Value root;
    std::ifstream conf(config_file, std::ifstream::binary);

    conf >> root;

    this->log_to_file = root["log_to_file"].asBool();
    this->log_file_name = root["log_file_path"].asString();
    this->log_to_console = root["log_to_console"].asBool();
    this->log_to_syslog = root["log_to_syslog"].asBool();

    return 0;
}

logger::logger(int argc, char **argv) : log_fp_(nullptr)
{
    int ret;

    // parse command line arguments
    while ((ret = getopt(argc, argv, "i:p:f:")) != -1) {
        switch (ret) {
            case 'i':
                this->config_server_ip_ = strdup(optarg);
            break;
            case 'p':
                this->config_server_port_ = std::stoi(optarg);
            break;
            case 'f':
                this->config_file_ = strdup(optarg);
            break;
            default:
                usage(argv[0]);
                return;
        }
    }

    ret = logger_config::instance()->parse(this->config_file_);
    if (ret != 0) {
        throw std::runtime_error("failed to parse configuration " +
                    std::string(this->config_file_) + "\n");
    }

    // create a server socket
    this->server_socket_ = std::make_shared<udp_server_socket>(
                                        this->config_server_ip_,
                                        this->config_server_port_);

    auto f1 = std::bind(&logger::log_thread, this);
    this->log_thread_ = std::make_shared<std::thread>(f1);
    this->log_thread_->detach();

    auto f2 = std::bind(&logger::rx_thread, this);
    this->rx_thread_ = std::make_shared<std::thread>(f2);
    this->rx_thread_->detach();

    this->initialized_ = true;
}

//
// Receive thread will wait for the log mmessages and queues
// them into the log queue. Soon as the messages are queued
// the receive thread interrupt the log_thread.
void logger::rx_thread()
{
    while (1) {
        log_buffer log_buf;
        int ret;

        memset(log_buf.buf, 0, sizeof(log_buf.buf));
        ret = this->server_socket_->udp_recv_from(log_buf.buf, sizeof(log_buf.buf), NULL);
        if (ret < 0) {
            continue;
        }

        std::unique_lock<std::mutex> l(this->log_queue_lock_);
        this->log_queue_.push(log_buf);
        this->log_queue_cond_.notify_one();
    }
}

//
// The log_thread will wait on the condition variable and receives the
// signal from the rx_thread.
//
// The log thread will then check and log to be written into the file
// or to console based on the configuration.
void logger::log_thread()
{
    logger_config *conf = logger_config::instance();

    while (1) {
        netos_log_info *info_msg;
        log_buffer log_buf;

        std::unique_lock<std::mutex> l(this->log_queue_lock_);
        this->log_queue_cond_.wait(l);

        while (!this->log_queue_.empty()) {
            log_buf = this->log_queue_.front();
            this->log_queue_.pop();

            info_msg = (netos_log_info *)log_buf.buf;

            if (conf->log_to_file) {
                this->log_to_file(info_msg);
            }

            if (conf->log_to_console) {
                this->log_to_console(info_msg);
            }

            if (conf->log_to_syslog) {
                this->log_to_syslog(info_msg);
            }
        }
    }
}

void logger::log_to_file(netos_log_info *info_msg)
{
    logger_config *conf = logger_config::instance();
    char filename[256] = {0};
    struct tm *tm;
    time_t t;

    if (!this->log_fp_) {
        t = time(NULL);
        tm = gmtime(&t);

        snprintf(filename,
                sizeof(filename),
                "%s_%04d_%02d_%02d_%02d_%02d_%02d.log",
                conf->log_file_name.c_str(),
                tm->tm_year + 1900,
                tm->tm_mon + 1,
                tm->tm_mday,
                tm->tm_hour,
                tm->tm_min,
                tm->tm_sec);

        this->log_fp_ = fopen(filename, "w");
        if (!this->log_fp_) {
            return;
        }
    }

    fprintf(this->log_fp_, "<%d>; %ju; %ju; %s",
                        info_msg->log_level,
                        info_msg->ts_sec,
                        info_msg->ts_nsec,
                        (char *)(info_msg->data));
    fflush(this->log_fp_);
}

void logger::log_to_console(netos_log_info *info_msg)
{
    std::string log_level_str = "Unknown";

    switch (info_msg->log_level) {
        case NETOS_LOG_LEVEL_VERBOSE:
            log_level_str = "Verbose";
        break;
        case NETOS_LOG_LEVEL_INFO:
            log_level_str = "Info";
        break;
        case NETOS_LOG_LEVEL_DEBUG:
            log_level_str = "Debug";
        break;
        case NETOS_LOG_LEVEL_WARNING:
            log_level_str = "Warning";
        break;
        case NETOS_LOG_LEVEL_ERROR:
            log_level_str = "Error";
        break;
    }

    fprintf(stderr, "<%s>, [%ju:%ju] %s",
                log_level_str.c_str(),
                info_msg->ts_sec,
                info_msg->ts_nsec,
                (char *)(info_msg->data));
}

void logger::log_to_syslog(netos_log_info *info_msg)
{
    int syslog_priority = LOG_INFO;

    // translate log level to syslog level
    switch (info_msg->log_level) {
        case NETOS_LOG_LEVEL_VERBOSE:
            syslog_priority = LOG_DEBUG;
        break;
        case NETOS_LOG_LEVEL_INFO:
            syslog_priority = LOG_INFO;
        break;
        case NETOS_LOG_LEVEL_DEBUG:
            syslog_priority = LOG_DEBUG;
        break;
        case NETOS_LOG_LEVEL_WARNING:
            syslog_priority = LOG_WARNING;
        break;
        case NETOS_LOG_LEVEL_ERROR:
            syslog_priority = LOG_ERR;
        break;
    }

    syslog(syslog_priority, "[%ju:%ju] %s",
                        info_msg->ts_sec,
                        info_msg->ts_nsec,
                        (char *)(info_msg->data));
}

logger::~logger()
{
}

void logger::run()
{
    if (!this->initialized_) {
        return;
    }

    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

}

}

int main(int argc, char **argv)
{
    netos::logging::logger l(argc, argv);

    l.run();

    return 0;
}

