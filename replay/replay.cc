#include <iostream>
#include <thread>
#include <string>
#include <stdint.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include "pcap_lib.h"
#include "raw_socket.h"
#include "replay.h"

static void usage(const char *progname)
{
    fprintf(stderr, "<%s> f:s \n"
                    "-f <filename> provide the pcap filename\n"
                    "-s <ifname> interface to replay the pcap files\n", progname);
}

int main(int argc, char **argv)
{
    std::string ifname;
    std::string filename;
    int ret;

    if (argc == 1) {
        usage(argv[0]);
        return -1;
    }

    while ((ret = getopt(argc, argv, "f:s:")) != -1) {
        switch (ret) {
            case 'f':
                filename = optarg;
            break;
            case 's':
                ifname = optarg;
            break;
            default:
                usage(argv[0]);
            return -1;
        }
    }

    if ((ifname == "") || (filename == "")) {
        usage(argv[0]);
        return -1;
    }

    netos::lib::raw_socket raw_sock(ifname, 0);
    netos::lib::pcap_reader rd(filename);

    while (1) {
        netos::lib::pcaprec_hdr_t rechdr;
        uint8_t pktbuf[4096];
        uint8_t dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        uint64_t delta;
        static struct timeval tv;

        ret = rd.read_packet(&rechdr, pktbuf, sizeof(pktbuf));
        if (ret < 0) {
            fprintf(stderr, "end of replay\n");
            break;
        }

        if ((tv.tv_sec == 0) && (tv.tv_usec == 0)) {
            delta = 0;
        } else {
            delta = (rechdr.ts_sec - tv.tv_sec) * 1000000 + (rechdr.ts_usec - tv.tv_usec);
        }
        tv.tv_sec = rechdr.ts_sec;
        tv.tv_usec = rechdr.ts_usec;

        std::this_thread::sleep_for(std::chrono::microseconds(delta));

        raw_sock.send_msg(dst, pktbuf, rechdr.orig_len);
    }
}
