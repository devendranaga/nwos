#ifndef IDS_PACKET_BUF_H
#define IDS_PACKET_BUF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ids_macro_defs.h"
#include "error_codes.h"

namespace netos {

#define NETOS_PACKET_BUF_SIZE 4096

using namespace netos::lib;

/**
 * Overlay structure for holding the packet.
 *
 * Provides helper routines to serialize and deserialize
 * the packet.
 *
 * Offset is used to maintain the buffer position where the transmit buffer
 * or receive buffer positions.
 *
 * Length is initialized to max when allocated. The real length of the frame is
 * only set in receive path.
 */
struct packet_buf {
    uint8_t *buf_;
    uint32_t offset_;
    uint32_t len_;
    packet_buf *next;

    netos_status allocate();
    void free_ptr();

    /**
     * Return the remaining length (after parsing as many possible layers).
     */
    uint32_t get_remaining_len() const;

    /**
     * Return the raw buffer.
     */
    uint8_t *get_raw_buf() const;

    /**
     * Return the raw buffer length.
     */
    uint32_t get_raw_buf_len() const;

    void serialize_bit(uint8_t bit_pos);
    void serialize_byte(uint8_t val);
    void serialize_bytes(uint8_t *bytes, uint32_t len);
    void serialize_mac(uint8_t *mac);
    void serialize_2_bytes(uint16_t val);
    void serialize_4_bytes(uint32_t val);

    void deserialize_byte(uint8_t *val);
    void deserialize_bytes(uint8_t *bytes, uint32_t len);
    void deserialize_mac(uint8_t *mac);
    void deserialize_2_bytes(uint16_t *val);
    void deserialize_4_bytes(uint32_t *val);
};

struct packet_buf_pool {
    public:
        static packet_buf_pool *instance() {
            static packet_buf_pool instance;
            return &instance;
        }

        ~packet_buf_pool() {}

        netos_status initialize(uint32_t size);
        packet_buf *get_pkt();
        void put_pkt(packet_buf *pkt);

    private:
        explicit packet_buf_pool() {}
        packet_buf *head_;
        uint32_t size_;
};

}

#endif
