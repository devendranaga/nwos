/**
 *
 * @brief - pcap reader and writer interface
 *
 * @author - Devendra Naga (devendra.aaru@gmail.com)
 */
#include <iostream>
#include <system_error>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <pcap_lib.h>
#include <logging.h>

namespace netos {

namespace lib {

pcap_writer::pcap_writer(const std::string &filename)
{
    pcap_hdr_t glob_hdr;

    glob_hdr = format_default_glob_header();

    fp = fopen(filename.c_str(), "w");
    if (!fp) {
        throw std::system_error(errno, std::generic_category());
    }

    fwrite(&glob_hdr, sizeof(glob_hdr), 1, fp);
}

pcap_writer::~pcap_writer()
{
    if (fp != nullptr) {
        fclose(fp);
    }
}

pcaprec_hdr_t pcap_writer::format_pcap_pkthdr(size_t pktsize)
{
    pcaprec_hdr_t rec_hdr;
    struct timeval tv;

    memset(&rec_hdr, 0, sizeof(rec_hdr));
    gettimeofday(&tv, 0);

    rec_hdr.ts_sec = tv.tv_sec;
    rec_hdr.ts_usec = tv.tv_usec;
    rec_hdr.incl_len = pktsize;
    rec_hdr.orig_len = pktsize;

    return rec_hdr;
}

int pcap_writer::write_packet(const pcaprec_hdr_t *rec, const uint8_t *buf)
{
    int ret;

    ret = fwrite(rec, sizeof(*rec), 1, fp);
    if (ret != 1) {
        return -1;
    }

    ret = fwrite(buf, rec->incl_len, 1, fp);
    if (ret != 1) {
        return -1;
    }

    return 0;
}

pcap_hdr_t pcap_writer::format_default_glob_header()
{
    pcap_hdr_t glob_hdr;

    memset(&glob_hdr, 0, sizeof(glob_hdr));
    glob_hdr.magic_number = 0xa1b2c3d4;
    glob_hdr.version_major = 2;
    glob_hdr.version_minor = 4;
    glob_hdr.thiszone = 0;
    glob_hdr.sigfigs = 0;
    glob_hdr.snaplen = 65535;
    glob_hdr.network = 1;

    return glob_hdr;
}

pcap_reader::pcap_reader(const std::string &filename)
{
    fp = fopen(filename.c_str(), "r");
    if (!fp) {
        throw std::system_error(errno, std::generic_category());
    }

    fread(&glob_hdr, sizeof(glob_hdr), 1, fp);
}

pcap_reader::~pcap_reader()
{
    if (fp != nullptr) {
        fclose(fp);
    }
}

int pcap_reader::read_packet(pcaprec_hdr_t *rec_hdr, uint8_t *buf, size_t buflen)
{
    int ret;

    ret = fread(rec_hdr, sizeof(*rec_hdr), 1, fp);
    if (ret != 1) {
        netos_log_error("failed to read record header\n");
        return -1;
    }

    ret = fread(buf, rec_hdr->incl_len, 1, fp);
    if (ret != 1) {
        netos_log_error("failed to read pcap data\n");
        return -1;
    }

    return 0;
}

}

}

#ifdef CONFIG_NC_PCAP_TESTING

int main(int argc, char **argv)
{
    std::string type, mode;
    int ret;

    type = std::string(argv[1]);
    mode = std::string(argv[2]);

    if (type == "read") {
        nc_pcap::nc_pcap_reader reader(mode);

        do {
            nc_pcap::pcaprec_hdr_t hdr;
            uint8_t buf[2048];

            ret = reader.read_packet(&hdr, buf, sizeof(buf));
            if (ret == -1) {
                break;
            }
        } while (1);
    } else if (type == "write") {
        nc_pcap::nc_pcap_writer writer(mode);
        int counter = 4;

        do {
            nc_pcap::pcaprec_hdr_t hdr;
            uint8_t buf[200];

            hdr = writer.format_pcap_pkthdr(200);

            ret = writer.write_packet(&hdr, buf);
            if (ret == -1) {
                break;
            }

            counter --;
        } while (counter > 0);
    }
}

#endif
