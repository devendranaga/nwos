#ifndef NETOS_PCAP_INTF_H
#define NETOS_PCAP_INTF_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

// PCAP Magic header
#define NETOS_PCAP_MAGIC_NUMBER_BE 0xA1B2C3D4
#define NETOS_PCAP_MAGIC_NUMBER_LE 0xD4C3B2A1

/**
 * @brief - PCAP global header.
 */
typedef struct __attribute__ ((__packed__)) {
    uint32_t    magic;         // Magic number (0xa1b2c3d4 or 0xd4c3b2a1)
    uint16_t    version_major; // Major version number
    uint16_t    version_minor; // Minor version number
    int32_t     thiszone;      // GMT to local correction
    uint32_t    sigfigs;       // Timestamp accuracy
    uint32_t    snaplen;       // Max snapshot length
    uint32_t    network;       // Link-layer header type (e.g., 1 for Ethernet)
} netos_pcap_global_header_t;

/**
 * @brief - PCAP packet header.
 */
typedef struct __attribute__ ((__packed__)) {
    uint32_t ts_sec;   // Timestamp seconds
    uint32_t ts_usec;  // Timestamp microseconds/nanoseconds
    uint32_t incl_len; // Number of bytes captured and saved in file
    uint32_t orig_len; // Actual length of packet on the wire
} netos_pcap_packet_header_t;

/**
 * @brief - Defines a pcap context.
 */
typedef struct {
    // valid fd until the netos_pcap_close_file is called
    int                         fd;
    // memory is mapped from the input file into this
    void                        *mapped_memory;

    // defines the file size in bytes
    uint32_t                    file_size;

    // offset bytes
    uint32_t                    offset;
    netos_pcap_global_header_t  *glob_hdr;
} netos_pcap_context_t;

netos_pcap_context_t *netos_pcap_open_file_to_read(const char *filename);

netos_pcap_context_t *netos_pcap_open_file_to_write(const char *filename,
                                                    uint32_t file_size);

netos_status_t netos_pcap_read_file_entry(netos_pcap_context_t *ctx,
                                          netos_pcap_packet_header_t **pkt_hdr,
                                          uint8_t **buf);

netos_status_t netos_pcap_write_file_entry(netos_pcap_context_t *ctx,
                                           uint8_t *buf,
                                           uint32_t buf_len,
                                           uint32_t ts_sec,
                                           uint32_t ts_usec);

void netos_pcap_close_file(netos_pcap_context_t *ctx);

#if defined(__cplusplus)
}
#endif

#endif

