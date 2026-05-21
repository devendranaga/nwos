#ifndef NETOS_PKTGEN_H
#define NETOS_PKTGEN_H

#include "raw_socket.h"

using namespace netos::lib;

namespace netos {

/**
 * @brief - Defines packet generator class.
 */
class pktgen {
    public:
        explicit pktgen() = default;
        ~pktgen() = default;

        void run(int argc, char **argv);

    private:
        void usage(const std::string &progname);
        void gen_eth();
        void gen_macsec();
        void gen_vlan();
        void gen_arp();
        void gen_avtp();
        void gen_ipv4();
        void gen_ipv6();
        void gen_icmp();
        void gen_tcp();
        void gen_udp();
        void gen_icmpv6();

        std::shared_ptr<netos::lib::raw_socket> raw_fd_;
};

}

#endif

