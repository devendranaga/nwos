#ifndef NETOS_PCAP_INTF_H
#define NETOS_PCAP_INTF_H

#include <stdio.h>
#include <stdint.h>

#define NETOS_PCAP_MAGIC_NUMBER_BE 0xA1B2C3D4
#define NETOS_PCAP_MAGIC_NUMBER_LE 0xD4C4B2A1

typedef struct {
    uint32_t magic;         // Magic number (0xa1b2c3d4 or 0xd4c3b2a1)
    uint16_t version_major; // Major version number
    uint16_t version_minor; // Minor version number
    int32_t  thiszone;      // GMT to local correction
    uint32_t sigfigs;       // Timestamp accuracy
    uint32_t snaplen;       // Max snapshot length
    uint32_t network;       // Link-layer header type (e.g., 1 for Ethernet)
} netos_pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;   // Timestamp seconds
    uint32_t ts_usec;  // Timestamp microseconds/nanoseconds
    uint32_t incl_len; // Number of bytes captured and saved in file
    uint32_t orig_len; // Actual length of packet on the wire
} netos_pcap_packet_header_t;

typedef struct {
    FILE *fp;
    netos_pcap_global_header_t glob_hdr;
} netos_pcap_context_t;

netos_pcap_context_t *netos_pcap_read_file(const char *filename);

netos_status_t netos_pcap_read_file_entry(netos_pcap_context_t *ctx,
                                          netos_pcap_packet_header_t *pkt_hdr,
                                          uint8_t *buf);

void netos_pcap_close_file(netos_pcap_context_t *ctx);

#endif

