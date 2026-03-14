#ifndef NETOS_TCPDUMP_H
#define NETOS_TCPDUMP_H

namespace netos {

struct tcp_dump_cmdargs {
    std::string ifname;
    std::string pcap_filename;
    std::string filter_file;

    void parse(int argc, char **argv);
};

}

#endif

