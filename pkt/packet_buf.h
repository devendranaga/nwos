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
struct packet_buf {

    uint8_t *buf_;
    uint32_t offset_;
    uint32_t len_;

    netos_status allocate();
    void free_ptr();

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

}

#endif
