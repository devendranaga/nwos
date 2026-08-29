#ifndef NETOS_PROTOCOLS_CHECKSUM_L4_H
#define NETOS_PROTOCOLS_CHECKSUM_L4_H

#include <stdint.h>
#include "netos_status.h"
#include "pkt_buffer.h"
#include "packet_parser.h"

netos_status_t netos_do_checksum_l4(uint16_t start_off,
                                    uint16_t remaining_len,
                                    netos_packet_parser_t *parsed_data,
                                    pkt_buffer_t *pkt_buf);

#endif

